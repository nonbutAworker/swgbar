#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "SWGBar verification"
echo "[1/6] Checking SQLite schema creation..."
sqlite3 :memory: < database/schema.sql

echo "[2/6] Parsing the RPC schema..."
python3 - <<'PYCODE'
import json
with open('contracts/rpc_schema.json') as source:
    schema = json.load(source)
print(f"Loaded {len(schema['rpc_methods'])} RPC method definitions.")
PYCODE

echo "[3/6] Running Go worker tests..."
(cd coreworker && go test -v ./...)

echo "[4/6] Running Swift tests..."
swift test

echo "[5/6] Checking app bundle signature integrity..."
codesign --verify --deep --strict build/SWGBar.app

echo "[6/6] Checking in-memory demo metrics..."
DEMO_JSON="$(mktemp)"
trap 'rm -f "$DEMO_JSON"' EXIT
build/SWGBar.app/Contents/MacOS/SWGBarApp --dump-demo > "$DEMO_JSON"
python3 - "$DEMO_JSON" <<'PYCODE'
import json
import sys

with open(sys.argv[1]) as source:
    data = json.load(source)
counts = data['counts']
n = sum(counts[key] for key in ('confirmed', 'suspected', 'publicPath', 'expectedPrivate', 'unknown'))
k = n - counts['unknown']
assert n == 1000, f'Expected 1,000 applicable samples, got {n}'
assert k == 800, f'Expected 800 classified samples, got {k}'
for key, expected in (
    ('confirmed_rate', 0.10),
    ('suspected_rate', 0.05),
    ('evidence_coverage', 0.80),
    ('classified_confirmed_rate', 0.125),
):
    assert abs(data[key]['ratio'] - expected) < 1e-6, f'Unexpected {key}'
print('Demo counts and rates match the expected values.')
PYCODE

echo "All verification steps passed."
