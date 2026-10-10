"""Turn a nextest JUnit report into an in-toto test-result predicate (T-38).

Predicate type: https://in-toto.io/attestation/test-result/v0.1
Usage: test-result-predicate.py <junit.xml> <run-url> <config-file>... > predicate.json
"""

import hashlib
import json
import pathlib
import sys
import xml.etree.ElementTree as ET


def main(args):
    if len(args) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    junit, url, configs = pathlib.Path(args[0]), args[1], args[2:]
    passed, failed = [], []
    for case in ET.parse(junit).getroot().iter("testcase"):
        name = f"{case.get('classname', '')}::{case.get('name', '')}"
        if case.find("skipped") is not None:
            continue
        if case.find("failure") is not None or case.find("error") is not None:
            failed.append(name)
        else:
            passed.append(name)
    configuration = []
    for config in configs:
        data = pathlib.Path(config).read_bytes()
        configuration.append({"name": config, "digest": {"sha256": hashlib.sha256(data).hexdigest()}})
    predicate = {
        "result": "FAILED" if failed else "PASSED",
        "configuration": configuration,
        "url": url,
        "passedTests": sorted(passed),
        "warnedTests": [],
        "failedTests": sorted(failed),
    }
    json.dump(predicate, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
