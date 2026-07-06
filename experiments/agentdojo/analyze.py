"""Read one or more results_*.json files and print the head-to-head table
plus the aiAuthZ block detail. Pure reporting over real run outputs."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def fmt(files):
    for fp in files:
        d = json.loads(Path(fp).read_text())
        cfg = d["config"]
        print("\n" + "=" * 78)
        print(f"MODEL: {cfg['model']}   suite={cfg['suite']}  attack={cfg['attack']}  "
              f"bench={cfg['benchmark_version']}")
        print(f"user_tasks={cfg['user_tasks']}")
        print(f"injection_tasks={cfg['injection_tasks']}")
        print("-" * 78)
        print(f"{'condition':<14}{'ASR':>8}{'clean_util':>12}{'util@attack':>13}"
              f"{'n_pairs':>9}{'n_ut':>6}{'blk_atk':>8}{'blk_cln':>8}")
        for r in d["results"]:
            print(f"{r['condition']:<14}{r['asr']*100:>7.1f}%{r['clean_utility']*100:>11.1f}%"
                  f"{r['utility_under_attack']*100:>12.1f}%{r['n_pairs']:>9}{r['n_user_tasks']:>6}"
                  f"{len(r['aiauthz_blocks_under_attack']):>8}{len(r['aiauthz_blocks_clean']):>8}")
        for r in d["results"]:
            succ = [k for k, v in r["security_results"].items() if v]
            if succ:
                print(f"  [{r['condition']}] injection SUCCEEDED on: {succ}")
            cf = [k for k, v in r["clean_utility_results"].items() if not v]
            if cf:
                print(f"  [{r['condition']}] benign task FAILED (clean) on: {cf}")
            if r["aiauthz_blocks_under_attack"]:
                print(f"  [{r['condition']}] aiAuthZ blocks under attack:")
                for b in r["aiauthz_blocks_under_attack"]:
                    print(f"      {b['tool']:<28} {b['reason']}")
            if r["aiauthz_blocks_clean"]:
                print(f"  [{r['condition']}] aiAuthZ blocks on benign (false positives):")
                for b in r["aiauthz_blocks_clean"]:
                    print(f"      {b['tool']:<28} {b['reason']}")


if __name__ == "__main__":
    files = sys.argv[1:] or sorted(str(p) for p in HERE.glob("results_*.json"))
    fmt(files)
