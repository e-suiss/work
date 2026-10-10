"""Fail when a SARIF file reports a high or critical security alert (T-38).

GitHub maps `security-severity` >= 7.0 to "high" and >= 9.0 to "critical". Results
whose rule has no security severity are reported but do not fail the gate.
Usage: sarif-gate.py <dir-or-file>...
"""

import json
import pathlib
import sys

THRESHOLD = 7.0


def sarif_files(args):
    for arg in args:
        path = pathlib.Path(arg)
        if path.is_dir():
            yield from sorted(path.rglob("*.sarif"))
        else:
            yield path


def main(args):
    if not args:
        print("usage: sarif-gate.py <dir-or-file>...", file=sys.stderr)
        return 2
    blocking = 0
    for file in sarif_files(args):
        sarif = json.loads(file.read_text(encoding="utf-8"))
        for run in sarif.get("runs", []):
            rules = {}
            driver = run.get("tool", {}).get("driver", {})
            for extension in [driver, *run.get("tool", {}).get("extensions", [])]:
                for rule in extension.get("rules", []):
                    rules[rule.get("id")] = rule
            for result in run.get("results", []):
                if result.get("suppressions"):
                    continue
                rule_id = result.get("ruleId") or result.get("rule", {}).get("id")
                rule = rules.get(rule_id, {})
                try:
                    severity = float(rule.get("properties", {}).get("security-severity", "0"))
                except ValueError:
                    severity = 0.0
                location = result.get("locations", [{}])[0].get("physicalLocation", {})
                where = "{}:{}".format(
                    location.get("artifactLocation", {}).get("uri", "?"),
                    location.get("region", {}).get("startLine", "?"),
                )
                message = result.get("message", {}).get("text", "").splitlines()[0:1]
                line = f"{rule_id} (security-severity {severity}) at {where}: {''.join(message)}"
                if severity >= THRESHOLD:
                    blocking += 1
                    print(f"::error::{line}")
                else:
                    print(f"::notice::{line}")
    if blocking:
        print(f"{blocking} high or critical finding(s)", file=sys.stderr)
        return 1
    print("no high or critical findings")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
