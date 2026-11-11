import argparse
import sys
import json
from datetime import date
from pathlib import Path
from triage.core import (
    load_semgrep_sarif,
    load_bandit,
    dedupe,
    load_suppressions,
    apply_suppressions,
    diff_baseline,
    gate
)

def main():
    parser = argparse.ArgumentParser(description="Diwan SAST triage and gate")
    parser.add_argument("--sarif", required=True)
    parser.add_argument("--bandit", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--equivalences", default=None)
    parser.add_argument("--baseline", default=None)
    parser.add_argument("--suppressions", default=None)
    parser.add_argument("--today", default=None)
    parser.add_argument("--fail-on", default="high")

    args = parser.parse_args()

    def read_json(path_str, expected_type):
        if not path_str:
            return expected_type()
        p = Path(path_str)
        if not p.is_file():
            sys.exit(2)
        try:
            with open(p, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            sys.exit(2)

    try:
        sarif_data_path = Path(args.sarif)
        bandit_data_path = Path(args.bandit)
        if not sarif_data_path.is_file() or not bandit_data_path.is_file():
            sys.exit(2)
        
        with open(sarif_data_path, 'r', encoding='utf-8') as f:
            json.load(f)
        with open(bandit_data_path, 'r', encoding='utf-8') as f:
            json.load(f)
    except Exception:
        sys.exit(2)

    equivalences = read_json(args.equivalences, dict)
    baseline_list = read_json(args.baseline, list)
    baseline_set = set(baseline_list) if isinstance(baseline_list, list) else set()
    suppressions_entries = read_json(args.suppressions, list)

    today = date.fromisoformat(args.today) if args.today else date.today()

    try:
        semgrep_findings = load_semgrep_sarif(args.sarif, args.project)
        bandit_findings = load_bandit(args.bandit, args.project)
        all_findings = semgrep_findings + bandit_findings

        groups = dedupe(all_findings, equivalences)
        valid_supps, invalid_supps = load_suppressions(suppressions_entries)
        active_groups, suppressed_groups = apply_suppressions(groups, valid_supps, today)
        new_groups, existing_groups, fixed = diff_baseline(active_groups, baseline_set)
        passed = gate(new_groups, args.fail_on)

        def group_to_dict(g):
            return {
                "key": g.key,
                "path": g.path,
                "line": g.line,
                "severity": g.severity,
                "tools": g.tools,
                "fingerprints": g.fingerprints
            }

        output = {
            "passed": passed,
            "new": [group_to_dict(g) for g in new_groups],
            "existing": [group_to_dict(g) for g in existing_groups],
            "suppressed": [group_to_dict(g) for g in suppressed_groups],
            "fixed": fixed,
            "invalid_suppressions": len(invalid_supps)
        }

        print(json.dumps(output))
        sys.exit(0 if passed else 1)
    except Exception:
        sys.exit(2)

if __name__ == "__main__":
    main()
