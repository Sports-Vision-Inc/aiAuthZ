# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

"""Tamper-evident audit log via a per-row hash chain.

Every audit record is appended through :func:`append_audit`, which stamps a
monotonic ``seq`` and a ``row_hash`` computed over the row's canonical fields
*and the previous row's* ``row_hash``. This makes the log tamper-**evident**:
deleting, reordering, or editing any historical row changes its hash and
therefore breaks every subsequent link, which :func:`verify_chain` detects.

This is the cryptographic backing for the "append-only" guarantee. It does not
by itself prevent a privileged operator from rewriting the whole table — for
that, publish the periodic ``head`` hash to an external append-only store
(object-lock bucket, transparency log, git). :func:`chain_head` returns the
value to anchor.

Concurrency: ``append_audit`` reads the current tail inside the caller's
transaction and flushes immediately so successive appends in one request chain
correctly. Under concurrent writers the appends must be serialized (SQLite does
this via its write lock; on Postgres take a per-scope advisory lock before
appending). The chain is single, global, and ordered by ``seq``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from aiauthz.db import models

# Genesis link for the very first row in an empty log.
GENESIS = "0" * 64


def _canonical(fields: dict) -> str:
    """Stable serialization of the hashed fields. Order-independent."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)


def compute_row_hash(*, seq: int, prev_hash: str, fields: dict) -> str:
    body = f"{prev_hash}\n{seq}\n{_canonical(fields)}"
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _ts(dt: datetime | None) -> str | None:
    """Canonical, round-trip-stable timestamp string. SQLite stores naive
    datetimes (tzinfo is dropped), so both the aware value written at append
    time and the naive value read back must normalize to the same string."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat()


def _hashed_fields(row: models.AuditLog) -> dict:
    """The subset of columns bound into the chain. Excludes id (random) and
    the chain columns themselves; includes everything an auditor relies on."""
    return {
        "timestamp": _ts(row.timestamp),
        "workspace_id": row.workspace_id,
        "actor_type": row.actor_type,
        "actor_id": row.actor_id,
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "decision": row.decision,
        "reason": row.reason,
        "request_hash": row.request_hash,
        "extra": row.extra,
    }


def append_audit(db: Session, **fields) -> models.AuditLog:
    """Append one audit row, chained to the current tail. Drop-in replacement
    for ``db.add(models.AuditLog(**fields))`` — but stamps seq/prev_hash/row_hash.
    Does not commit; the caller's transaction owns the commit."""
    row = models.AuditLog(**fields)
    if row.timestamp is None:
        row.timestamp = datetime.now(timezone.utc)

    tail = (
        db.query(models.AuditLog)
        .order_by(models.AuditLog.seq.desc())
        .limit(1)
        .first()
    )
    last_seq = tail.seq if (tail and tail.seq is not None) else 0
    prev_hash = tail.row_hash if (tail and tail.row_hash) else GENESIS

    row.seq = last_seq + 1
    row.prev_hash = prev_hash
    row.row_hash = compute_row_hash(seq=row.seq, prev_hash=prev_hash, fields=_hashed_fields(row))

    db.add(row)
    db.flush()  # so the next append in this transaction sees this row as tail
    return row


def verify_chain(db: Session, *, limit: int | None = None) -> dict:
    """Recompute the chain from genesis and report the first break, if any."""
    q = db.query(models.AuditLog).order_by(models.AuditLog.seq.asc())
    if limit:
        q = q.limit(limit)
    rows = q.all()

    prev_hash = GENESIS
    expected_seq = 1
    for row in rows:
        if row.seq is None or row.row_hash is None:
            # Pre-chain legacy row; skip but note it is unprotected.
            continue
        if row.seq != expected_seq:
            return _broken(row, "seq_gap", expected_seq, len(rows))
        if row.prev_hash != prev_hash:
            return _broken(row, "prev_hash_mismatch", expected_seq, len(rows))
        recomputed = compute_row_hash(
            seq=row.seq, prev_hash=row.prev_hash, fields=_hashed_fields(row)
        )
        if recomputed != row.row_hash:
            return _broken(row, "row_hash_mismatch", expected_seq, len(rows))
        prev_hash = row.row_hash
        expected_seq += 1

    return {
        "valid": True,
        "count": len(rows),
        "head_hash": prev_hash if rows else GENESIS,
        "broken_at": None,
        "reason": None,
    }


def _broken(row, reason, seq, count) -> dict:
    return {
        "valid": False,
        "count": count,
        "head_hash": None,
        "broken_at": {"id": row.id, "seq": row.seq},
        "reason": reason,
    }


def chain_head(db: Session) -> str:
    """Return the current head hash — the value to anchor externally."""
    tail = (
        db.query(models.AuditLog)
        .filter(models.AuditLog.row_hash.isnot(None))
        .order_by(models.AuditLog.seq.desc())
        .limit(1)
        .first()
    )
    return tail.row_hash if tail else GENESIS
