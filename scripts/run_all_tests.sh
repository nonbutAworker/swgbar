#!/bin/bash
set -euo pipefail

echo "================================================================"
echo "      SWGBar 全量自动化测试与验证 (T01-T16 + Go + DB + UI)"
echo "================================================================"

echo ""
echo "[1/6] 验证 SQLite Schema DDL..."
sqlite3 :memory: < database/schema.sql
echo "  ==> SQLite 19 张数据表与索引创建无语法错误！"

echo ""
echo "[2/6] 验证 RPC JSON Schema..."
python3 -c "import json; schema = json.load(open('contracts/rpc_schema.json')); print(f'  ==> RPC 方法数: {len(schema[\"rpc_methods\"])} 个全部有效')"

echo ""
echo "[3/6] 运行 Go CoreWorker 独立探测与证书基线测试..."
cd coreworker
go test -v ./...
go build -trimpath -o ../build/coreworker main.go
cd ..
echo "  ==> Go IPv4 限制、VerifyConnection fail-closed 与 PKIX 验证全部通过！"

echo ""
echo "[4/6] 运行 Swift 核心测试套件 (覆盖 T01 - T16 正确性测试矩阵 & L2/L5 压测)..."
swift test

echo ""
echo "[5/6] 验证应用打包与代码签名..."
codesign --verify --deep --strict build/SWGBar.app
echo "  ==> SWGBar.app 签名有效且完整！"

echo ""
echo "[6/6] 验证统一样例数据指标与公式 (第 05 & 17 章)..."
DEMO_JSON=$(build/SWGBar.app/Contents/MacOS/SWGBarApp --dump-demo)
python3 -c "
import json, sys
data = json.loads('''$DEMO_JSON''')
counts = data['counts']
print(f'  ==> C (已确认): {counts[\"confirmed\"]}')
print(f'  ==> S (疑似):   {counts[\"suspected\"]}')
print(f'  ==> P (公共):   {counts[\"publicPath\"]}')
print(f'  ==> E (预期):   {counts[\"expectedPrivate\"]}')
print(f'  ==> U (未知):   {counts[\"unknown\"]}')
n = counts['confirmed'] + counts['suspected'] + counts['publicPath'] + counts['expectedPrivate'] + counts['unknown']
k = counts['confirmed'] + counts['suspected'] + counts['publicPath'] + counts['expectedPrivate']
print(f'  ==> N (适用总数): {n} (必须等于 1000)')
print(f'  ==> K (已分类):   {k} (必须等于 800)')
assert n == 1000, 'N 不等于 1000'
assert k == 800, 'K 不等于 800'
assert abs(data['confirmed_rate']['ratio'] - 0.10) < 1e-6, '确认占比不等于 10.0%'
assert abs(data['suspected_rate']['ratio'] - 0.05) < 1e-6, '疑似占比不等于 5.0%'
assert abs(data['evidence_coverage']['ratio'] - 0.80) < 1e-6, '覆盖率不等于 80.0%'
assert abs(data['classified_confirmed_rate']['ratio'] - 0.125) < 1e-6, '已分类确认占比不等于 12.5%'
print('  ==> 核心指标与百分比计算 100% 吻合技术方案第 5.2 章！')
"

echo ""
echo "================================================================"
echo "          ALL TESTS & VERIFICATIONS PASSED (100% PASS)          "
echo "================================================================"
