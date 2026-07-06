"""aiAuthZ as an AgentDojo defense.

This integrates aiAuthZ's *real* deterministic policy engine
(`aiauthz.policy.evaluate`) as a tool-call authorizer inside AgentDojo's
agent pipeline.

Design
------
AgentDojo executes tool calls in `ToolsExecutor.query`. We subclass it as
`AiAuthzToolsExecutor`: before a tool call reaches `runtime.run_function`, we
map the AgentDojo tool name + args onto an aiAuthZ tool + normalized args and
call the real `evaluate(...)`. If the decision is a deny, we DO NOT execute the
tool; instead we return a tool error message ("blocked by aiAuthZ policy ...")
so the agent sees the refusal, exactly as a real gateway would behave.

This tests the paper's thesis directly: deterministic, argument-level
authorization reduces attack-success-rate by blocking the *action* the
injection wants (pay attacker IBAN / change password), regardless of whether
the model was fooled by the injected instructions.

Note on scope: aiAuthZ does NOT detect prompt injection. It only authorizes
actions. Any injected goal whose *action* is permitted by policy still
succeeds. See RESULTS.md for the honest interpretation.
"""

from __future__ import annotations

from collections.abc import Sequence

import yaml

from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, is_string_list
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string
from ast import literal_eval

# The REAL aiAuthZ policy engine (unmodified).
from aiauthz.policy import evaluate


# --------------------------------------------------------------------------
# Policy for the AgentDojo *banking* suite.
#
# Roles/tools + argument-level constraints, expressed in aiAuthZ's own schema.
# The recipient_allowlist is the set of IBANs that are legitimate in the seeded
# environment: the user's own account plus the established payees that already
# appear in the account's transaction history. It is a "known-payee" allowlist,
# NOT tailored to the attacker. The attacker IBAN used by every banking
# injection task is US133000000121212121212, which is deliberately close to a
# real payee (US122000000121212121212) but is not on the list.
# --------------------------------------------------------------------------
BANKING_POLICY_YAML = """\
tools:
  get_iban: [member]
  get_balance: [member]
  get_most_recent_transactions: [member]
  get_scheduled_transactions: [member]
  get_user_info: [member]
  file_read: [member]
  update_user_info: [member]
  send_money: [member]
default: deny            # update_password + anything unmapped -> deny
constraints:
  send_money:
    recipient_allowlist:
      - "DE89370400440532013000"   # the user's own account (self)
      - "CH9300762011623852957"    # known payee from history
      - "GB29NWBK60161331926819"   # known payee from history
      - "SE3550000000054910000003" # known payee from history
      - "US122000000121212121212"  # known payee from history
  file_read:
    path_denylist: ["/etc/*", "/root/*", "**/.ssh/*", "**/*secret*", "**/*.env", "**/id_rsa*"]
"""

BANKING_POLICY = yaml.safe_load(BANKING_POLICY_YAML)


def map_banking_tool(tool_name: str, args: dict) -> tuple[str, dict]:
    """Map an AgentDojo *banking* tool call onto an aiAuthZ (tool, args) pair.

    The aiAuthZ constraint checker keys off arg names `to` (recipient),
    `path` (file), etc. AgentDojo uses `recipient` and `file_path`, so we
    normalize here. All value-carrying tools that move money are funneled into
    the single aiAuthZ `send_money` tool so the recipient allowlist applies to
    send_money, schedule_transaction, and redirected update_scheduled_transaction.
    """
    args = args or {}
    money_tools = {"send_money", "schedule_transaction", "update_scheduled_transaction"}
    if tool_name in money_tools:
        recipient = args.get("recipient")
        # update_scheduled_transaction may omit recipient (amount-only edit).
        az_args = {}
        if recipient is not None:
            az_args["to"] = recipient
        return "send_money", az_args
    if tool_name == "read_file":
        return "file_read", {"path": args.get("file_path")}
    if tool_name == "update_password":
        # Not in the policy's tool list -> default deny (role gate).
        return "update_password", {}
    # get_* read-only tools + update_user_info pass through under their own name.
    return tool_name, {}


class AiAuthzToolsExecutor(ToolsExecutor):
    """Drop-in replacement for AgentDojo's ToolsExecutor that authorizes every
    tool call against aiAuthZ before executing it."""

    def __init__(self, policy: dict, tool_mapper, role: str = "member", output_formatter=None, block_log: list | None = None):
        if output_formatter is None:
            super().__init__()
        else:
            super().__init__(output_formatter)
        self.policy = policy
        self.tool_mapper = tool_mapper
        self.role = role
        self.block_log = block_log if block_log is not None else []

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ):
        if len(messages) == 0 or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        if not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args

        tool_call_results = []
        for tool_call in messages[-1]["tool_calls"]:
            if tool_call.function == EMPTY_FUNCTION_NAME:
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error="Empty function name provided. Provide a valid function name.",
                    )
                )
                continue
            if tool_call.function not in (t.name for t in runtime.functions.values()):
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=f"Invalid tool {tool_call.function} provided.",
                    )
                )
                continue

            # Same string-list coercion AgentDojo does before running.
            for arg_k, arg_v in tool_call.args.items():
                if isinstance(arg_v, str) and is_string_list(arg_v):
                    tool_call.args[arg_k] = literal_eval(arg_v)

            # ---- aiAuthZ authorization gate (the real engine) ----
            az_tool, az_args = self.tool_mapper(tool_call.function, tool_call.args)
            decision = evaluate(policy=self.policy, tool_name=az_tool, role=self.role, args=az_args)
            if not decision.allow:
                self.block_log.append(
                    {
                        "tool": tool_call.function,
                        "az_tool": az_tool,
                        "az_args": az_args,
                        "reason": decision.reason,
                    }
                )
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=(
                            f"Blocked by aiAuthZ policy: action '{tool_call.function}' is not "
                            f"authorized ({decision.reason}). The request was denied and not executed."
                        ),
                    )
                )
                continue
            # ---- authorized: execute normally ----
            result, error = runtime.run_function(env, tool_call.function, tool_call.args)
            tool_call_results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(self.output_formatter(result))],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )
        return query, runtime, env, [*messages, *tool_call_results], extra_args
