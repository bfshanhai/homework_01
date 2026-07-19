#!/bin/bash
# ===================================================================
# 本地安全检查脚本 — 开发提交前执行
# 模拟 CI/CD 流水线的安全校验步骤
# ===================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

FAILED=0

echo -e "${YELLOW}══════════════════════════════════════════════${NC}"
echo -e "${YELLOW}   🔒 安全审计流水线 — 本地执行              ${NC}"
echo -e "${YELLOW}══════════════════════════════════════════════${NC}"
echo ""

# -------------------------------------------------------
# 步骤 1: Bandit 静态安全审计
# -------------------------------------------------------
echo -e "${YELLOW}[Step 1/4] Bandit 静态安全审计 ...${NC}"
if bandit -c .bandit -r app.py -f txt 2>/dev/null; then
    echo -e "${GREEN}  ✅ Bandit 审计通过${NC}"
else
    echo -e "${RED}  ❌ Bandit 发现安全问题${NC}"
    FAILED=1
fi
echo ""

# -------------------------------------------------------
# 步骤 2: 安全单元测试
# -------------------------------------------------------
echo -e "${YELLOW}[Step 2/4] 安全单元测试 (pytest) ...${NC}"
export SECRET_KEY="local-check-key-for-test-1234567890!!"
if python -m pytest tests/test_security.py -v --tb=short 2>&1; then
    echo -e "${GREEN}  ✅ 安全测试全部通过${NC}"
else
    echo -e "${RED}  ❌ 安全测试存在失败用例${NC}"
    FAILED=1
fi
echo ""

# -------------------------------------------------------
# 步骤 3: 硬编码密钥检测
# -------------------------------------------------------
echo -e "${YELLOW}[Step 3/4] 硬编码密钥检测 ...${NC}"
SECRET_LEAKS=$(grep -rnP '(secret_key\s*=\s*"|password\s*=\s*"[^}]|api_key\s*=\s*")' app.py \
    | grep -v 'os.getenv\|os.environ' || true)
if [ -z "$SECRET_LEAKS" ]; then
    echo -e "${GREEN}  ✅ 未发现硬编码密钥${NC}"
else
    echo -e "${RED}  ❌ 发现可能的硬编码密钥:${NC}"
    echo "$SECRET_LEAKS"
    FAILED=1
fi
echo ""

# -------------------------------------------------------
# 步骤 4: 明文密码检查
# -------------------------------------------------------
echo -e "${YELLOW}[Step 4/4] 明文密码存储检测 ...${NC}"
PLAINTEXT=$(grep -rnP '"password"\s*:\s*"[^$]' app.py || true)
if [ -z "$PLAINTEXT" ]; then
    echo -e "${GREEN}  ✅ 未发现明文密码存储 (均使用 bcrypt 哈希)${NC}"
else
    echo -e "${RED}  ❌ 发现可能的明文密码:${NC}"
    echo "$PLAINTEXT"
    FAILED=1
fi
echo ""

# -------------------------------------------------------
# 汇总
# -------------------------------------------------------
echo -e "${YELLOW}══════════════════════════════════════════════${NC}"
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}  ✅ 全部安全检查通过 — 可以提交${NC}"
else
    echo -e "${RED}  ❌ 安全检查未通过 — 请修复后重试${NC}"
fi
echo -e "${YELLOW}══════════════════════════════════════════════${NC}"
exit $FAILED
