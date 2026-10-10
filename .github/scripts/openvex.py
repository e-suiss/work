"""Build the release's OpenVEX document (T-38).

Statements come from the tracked file (an array of OpenVEX statements without
`products`); every statement is applied to every product of this release.
Usage: openvex.py <statements.json> <doc-id> <author> <timestamp> <product-purl>... > vex.json
"""

import json
import pathlib
import sys


def main(args):
    if len(args) < 5:
        print(__doc__, file=sys.stderr)
        return 2
    statements_file, doc_id, author, timestamp, products = args[0], args[1], args[2], args[3], args[4:]
    statements = json.loads(pathlib.Path(statements_file).read_text(encoding="utf-8"))
    if not isinstance(statements, list):
        print("statements file must contain a JSON array", file=sys.stderr)
        return 1
    product_list = [{"@id": purl} for purl in products]
    out = []
    for statement in statements:
        statement = dict(statement)
        statement["products"] = product_list
        statement.setdefault("timestamp", timestamp)
        out.append(statement)
    document = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": doc_id,
        "author": author,
        "timestamp": timestamp,
        "version": 1,
        "tooling": "e-suiss/access release workflow",
        "statements": out,
    }
    json.dump(document, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
