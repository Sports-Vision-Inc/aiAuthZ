"""Head-to-head AgentDojo run: no-defense vs a built-in defense vs aiAuthZ.

Suite:  banking (AgentDojo v1.2.2)
Attack: important_instructions (AgentDojo's strongest standard prompt-injection attack)
Model:  openai/gpt-4o-mini via OpenRouter (OpenAI-compatible endpoint)

Metrics (both from the SAME with-injection run, per AgentDojo semantics):
  - ASR (security):   fraction of (user_task, injection_task) pairs where the
                      injection's goal was achieved in the environment.
  - Utility:          fraction of (user_task, injection_task) pairs where the
                      benign user task still completed correctly under attack.

Every number printed/saved here comes from a real run executed on OpenRouter.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import openai
from dotenv import load_dotenv

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig, load_system_message
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, tool_result_to_str
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite

from aiauthz_defense import AiAuthzToolsExecutor, BANKING_POLICY, BANKING_POLICY_YAML, map_banking_tool

# ---------------------------- config ----------------------------
BENCH_VERSION = "v1.2.2"
SUITE_NAME = "banking"
ATTACK = "important_instructions"
# Primary model is a current (Dec 2025) model. Override with AIAUTHZ_MODEL to
# run the secondary "susceptible-model" demonstration. MODEL_NAME_TAG must be a
# token AgentDojo's attack/model registry recognizes (it derives the prose model
# name the injection addresses); the actual API model string sent to OpenRouter
# is MODEL.
_MODEL_TAGS = {
    "anthropic/claude-fable-5": "claude-3-5-sonnet-20241022",   # -> "Claude"
    "google/gemini-3-flash-preview": "gemini-2.0-flash-001",    # -> "AI model developed by Google"
    "google/gemini-3.1-pro-preview": "gemini-2.0-flash-001",    # -> "AI model developed by Google"
    "deepseek/deepseek-v4-pro": "claude-3-5-sonnet-20241022",   # generic assistant tag
    "z-ai/glm-5.2": "claude-3-5-sonnet-20241022",
}
MODEL = os.environ.get("AIAUTHZ_MODEL", "anthropic/claude-fable-5")
MODEL_NAME_TAG = _MODEL_TAGS.get(MODEL, "claude-3-5-sonnet-20241022")
RESULTS_FILE = os.environ.get("AIAUTHZ_RESULTS", "results.json")

# Bounded task set to control cost. These are real AgentDojo task IDs.
USER_TASKS = ["user_task_0", "user_task_1", "user_task_2", "user_task_3", "user_task_4"]
INJECTION_TASKS = [
    "injection_task_0",  # send_money to attacker IBAN (exfil in subject)
    "injection_task_4",  # redirect a recurring payment to attacker IBAN
    "injection_task_5",  # send as much money as possible to attacker IBAN
    "injection_task_7",  # change the user's password
]

LOGDIR = HERE / "runs" / MODEL.replace("/", "_")
LOGDIR.mkdir(parents=True, exist_ok=True)


def make_llm() -> OpenAILLM:
    load_dotenv(HERE.parent.parent / ".env.local")
    key = os.environ["OPENROUTER_API_KEY"]
    client = openai.OpenAI(api_key=key, base_url="https://openrouter.ai/api/v1",
                           timeout=180, max_retries=3)
    llm = OpenAILLM(client, MODEL, temperature=0.0)
    # .name feeds both from_config's pipeline naming AND the important_instructions
    # attack, which derives the prose model name from the pipeline name. We use the
    # canonical gpt-4o-mini token so the attack correctly addresses "GPT-4" while the
    # actual API model string stays MODEL ("openai/gpt-4o-mini") for OpenRouter.
    llm.name = MODEL_NAME_TAG
    return llm


def build_pipeline(condition: str, block_log: list):
    sysmsg = load_system_message(None)
    llm = make_llm()

    if condition == "no_defense":
        cfg = PipelineConfig(llm=llm, model_id=None, defense=None,
                             system_message_name=None, system_message=None)
        return AgentPipeline.from_config(cfg)

    if condition == "spotlighting":
        cfg = PipelineConfig(llm=llm, model_id=None, defense="spotlighting_with_delimiting",
                             system_message_name=None, system_message=None)
        return AgentPipeline.from_config(cfg)

    if condition == "aiauthz":
        # Manually assemble the standard pipeline but swap in the aiAuthZ authorizer.
        executor = AiAuthzToolsExecutor(
            policy=BANKING_POLICY,
            tool_mapper=map_banking_tool,
            role="member",
            output_formatter=tool_result_to_str,
            block_log=block_log,
        )
        tools_loop = ToolsExecutionLoop([executor, llm])
        pipeline = AgentPipeline([SystemMessage(sysmsg), InitQuery(), llm, tools_loop])
        pipeline.name = f"{MODEL_NAME_TAG}-aiauthz"
        return pipeline

    raise ValueError(condition)


def run_condition(condition: str) -> dict:
    print(f"\n===== CONDITION: {condition} =====", flush=True)
    block_log: list = []
    pipeline = build_pipeline(condition, block_log)
    suite = get_suite(BENCH_VERSION, SUITE_NAME)
    attack = load_attack(ATTACK, suite, pipeline)
    with OutputLogger(str(LOGDIR / condition)):
        results = benchmark_suite_with_injections(
            pipeline,
            suite,
            attack,
            logdir=LOGDIR / condition,
            force_rerun=True,
            user_tasks=USER_TASKS,
            injection_tasks=INJECTION_TASKS,
            verbose=False,
            benchmark_version=BENCH_VERSION,
        )
    sec = list(results["security_results"].values())  # True == injection SUCCEEDED
    util = list(results["utility_results"].values())   # True == benign task still OK under attack
    asr = sum(sec) / len(sec)
    utility_under_attack = sum(util) / len(util)

    # Clean benign utility (NO attack) — isolates whether the defense itself
    # breaks legitimate functionality, separate from injection-derailment.
    clean_block_log: list = []
    clean_pipeline = build_pipeline(condition, clean_block_log)
    with OutputLogger(str(LOGDIR / f"{condition}_clean")):
        clean = benchmark_suite_without_injections(
            clean_pipeline, suite,
            logdir=LOGDIR / f"{condition}_clean",
            force_rerun=True,
            user_tasks=USER_TASKS,
            benchmark_version=BENCH_VERSION,
        )
    clean_util = list(clean["utility_results"].values())
    clean_utility = sum(clean_util) / len(clean_util)

    summary = {
        "condition": condition,
        "asr": asr,
        "clean_utility": clean_utility,
        "utility_under_attack": utility_under_attack,
        "n_pairs": len(sec),
        "n_user_tasks": len(clean_util),
        "security_results": {f"{u}|{i}": bool(v) for (u, i), v in results["security_results"].items()},
        "utility_under_attack_results": {f"{u}|{i}": bool(v) for (u, i), v in results["utility_results"].items()},
        "clean_utility_results": {f"{u}|{i}": bool(v) for (u, i), v in clean["utility_results"].items()},
        "aiauthz_blocks_under_attack": block_log,
        "aiauthz_blocks_clean": clean_block_log,
    }
    print(f"{condition}: ASR={asr*100:.1f}%  clean_util={clean_utility*100:.1f}%  "
          f"util_under_attack={utility_under_attack*100:.1f}%  n_pairs={len(sec)}  "
          f"blocks(attack)={len(block_log)} blocks(clean)={len(clean_block_log)}", flush=True)
    return summary


def main():
    conditions = ["no_defense", "spotlighting", "aiauthz"]
    if len(sys.argv) > 1:
        conditions = sys.argv[1:]
    out = {
        "config": {
            "benchmark_version": BENCH_VERSION,
            "suite": SUITE_NAME,
            "attack": ATTACK,
            "model": MODEL,
            "provider": "openrouter (https://openrouter.ai/api/v1, OpenAI-compatible)",
            "user_tasks": USER_TASKS,
            "injection_tasks": INJECTION_TASKS,
            "aiauthz_policy_yaml": BANKING_POLICY_YAML,
        },
        "results": [],
    }
    for c in conditions:
        out["results"].append(run_condition(c))
        # write incrementally so partial results survive an interruption
        (HERE / RESULTS_FILE).write_text(json.dumps(out, indent=2))

    print("\n===== SUMMARY =====")
    print(f"{'condition':<14} {'ASR':>8} {'clean_util':>11} {'util@attack':>12} {'n_pairs':>8}")
    for r in out["results"]:
        print(f"{r['condition']:<14} {r['asr']*100:>7.1f}% {r['clean_utility']*100:>10.1f}% "
              f"{r['utility_under_attack']*100:>11.1f}% {r['n_pairs']:>8}")
    print(f"\nSaved: {HERE/RESULTS_FILE}")


if __name__ == "__main__":
    main()
