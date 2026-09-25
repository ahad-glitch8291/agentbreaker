"""
compare_results.py
-------------------
Compares two results.json files (produced by run_attacks.py --save ...) side by
side. Meant for the Phase 3 before/after story: same model, same attacks, only
the system prompt (baseline vs. hardened) differs.

Usage:
    python3 compare_results.py results_before.json results_after.json
"""

import sys
import json


def load(path: str) -> dict:
    with open(path) as f:
        data = json.load(f)
    return {r["id"]: r for r in data["results"]}


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 compare_results.py <before.json> <after.json>")
        sys.exit(1)

    before = load(sys.argv[1])
    after = load(sys.argv[2])

    ids = sorted(set(before.keys()) | set(after.keys()))

    before_leaks = sum(1 for r in before.values() if r["succeeded"])
    after_leaks = sum(1 for r in after.values() if r["succeeded"])

    print(f"\n{'#' * 70}")
    print("# BEFORE / AFTER COMPARISON")
    print(f"{'#' * 70}\n")
    print(f"Before ({sys.argv[1]}): {before_leaks}/{len(before)} attacks leaked")
    print(f"After  ({sys.argv[2]}): {after_leaks}/{len(after)} attacks leaked\n")

    print(f"{'ID':<10}{'Name':<32}{'Before':<12}{'After':<12}{'Change'}")
    print("-" * 78)
    for attack_id in ids:
        b = before.get(attack_id)
        a = after.get(attack_id)
        b_status = "🔴 LEAKED" if (b and b["succeeded"]) else ("🟢 held" if b else "n/a")
        a_status = "🔴 LEAKED" if (a and a["succeeded"]) else ("🟢 held" if a else "n/a")

        if b and a:
            if b["succeeded"] and not a["succeeded"]:
                change = "✅ FIXED"
            elif not b["succeeded"] and a["succeeded"]:
                change = "⚠️  NEW LEAK"
            else:
                change = "—"
        else:
            change = "—"

        name = b["name"] if b else a["name"]
        print(f"{attack_id:<10}{name:<32}{b_status:<12}{a_status:<12}{change}")

    print()


if __name__ == "__main__":
    main()
