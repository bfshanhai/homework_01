# 🔒 越权与业务逻辑漏洞安全修复报告

> **项目名称：** 用户信息管理平台（Python Flask）
> **项目路径：** `/opt/Class01`
> **报告版本：** v5.0 — 权限安全修复版
> **报告日期：** 2026-07-22
> **漏洞编号：** HC-AUTH-01 ~ HC-AUTH-05

---

## 目录

1. [漏洞概述](#1-漏洞概述)
2. [漏洞详情与风险分析](#2-漏洞详情与风险分析)
3. [漏洞复现过程](#3-漏洞复现过程)
4. [修复方案](#4-修复方案)
5. [修复前后代码对比](#5-修复前后代码对比)
6. [安全测试验证](#6-安全测试验证)
7. [长效防御措施](#7-长效防御措施)

---

## 1. 漏洞概述

| 漏洞编号 | 漏洞类型 | CWE | CVSS 3.1 | 风险等级 |
|---------|---------|-----|----------|---------|
| **HC-AUTH-01** | 水平越权 — 个人资料 IDOR | CWE-639 | 8.1 | 🔴 High |
| **HC-AUTH-02** | 跨角色越权 — 管理员资料泄露 | CWE-284 | 8.1 | 🔴 High |
| **HC-AUTH-03** | 充值接口对象级授权缺失 | CWE-639 | 7.5 | 🔴 High |
| **HC-AUTH-04** | 负数充值逻辑缺陷 | CWE-20 | 5.3 | 🟡 Medium |
| **HC-AUTH-05** | CSRF 跨站请求伪造 | CWE-352 | 8.8 | 🔴 High |

### 攻击路径总图

```
攻击者
  │
  ├──▶ HC-AUTH-01: /profile?user_id=2 查看他人资料
  │      └──▶ 窃取任意用户的邮箱、手机、余额
  │
  ├──▶ HC-AUTH-02: /profile?user_id=1 查看管理员
  │      └──▶ 跨角色信息泄露
  │
  ├──▶ HC-AUTH-03: /recharge user_id=1 修改他人余额
  │      └──▶ 任意账户资金篡改
  │
  ├──▶ HC-AUTH-04: /recharge amount=-99999 扣款
  │      └──▶ 恶意扣款、制造负余额
  │
  └──▶ HC-AUTH-05: CSRF 诱导管理员充值
         └──▶ 无感知资金操作
```

---

## 2. 漏洞详情与风险分析

### HC-AUTH-01: 水平越权 — 个人资料 IDOR (CWE-639)

**漏洞原代码：**

```python
@app.route("/profile")
def profile():
    user_id = request.args.get("user_id")  # ← 信任 URL 参数
    # 根据 user_id 查询数据库...
    c.execute("SELECT ... FROM users WHERE id = ?", (user_id,))
```

**风险分析：** 未校验当前登录用户与查询的 `user_id` 是否匹配，攻击者遍历 `user_id` 即可获取全站用户的敏感信息。

| 攻击 URL | 结果 |
|---------|------|
| `/profile?user_id=2` | ❌ 查看 alice 的邮箱、手机、余额 |
| `/profile?user_id=3` | ❌ 查看任意注册用户的资料 |

### HC-AUTH-02: 跨角色越权 (CWE-284)

**风险分析：** 普通用户通过修改 `user_id=1` 可直接查看管理员 `admin` 的完整资料（含余额 ¥99999），攻击者可定位高价值目标。

### HC-AUTH-03: 充值接口对象级授权缺失 (CWE-639)

**漏洞原代码：**

```python
@app.route("/recharge", methods=["POST"])
def recharge():
    user_id = request.form.get("user_id")  # ← 完全信任表单参数
    amount = request.form.get("amount")
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
```

**风险分析：** 充值表单的 `user_id` 隐藏字段可被攻击者任意修改，向其他用户账户充值或篡改他人余额。

### HC-AUTH-04: 负数充值逻辑缺陷 (CWE-20)

**风险分析：**

```python
# 无金额正负校验
c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
```

| 提交数据 | 结果 |
|---------|------|
| `amount=-500` | ❌ 从目标账户扣款 ¥500 |
| `amount=-99999` | ❌ 管理员余额清零 |
| `amount=0` | ❌ 无意义调用日志污染 |

### HC-AUTH-05: CSRF 跨站请求伪造 (CWE-352)

**风险分析：** 充值接口为纯 POST 无校验 token，攻击者可构造恶意页面：

```html
<form action="https://app/recharge" method="POST">
  <input name="user_id" value="1">
  <input name="amount" value="10000">
</form>
<script>document.forms[0].submit()</script>
```

诱导已登录的管理员访问该页面 → 自动充值 `admin` 账户 → 攻击者获益。

---

## 3. 漏洞复现过程

### HC-AUTH-01/02: 水平+垂直越权

```bash
# 以 alice 身份登录
$ curl -sk -X POST https://localhost:5000/login \
  -d "username=alice&password=alice2025" -c cookies.txt

# 查看管理员资料（修复前）
$ curl -sk "https://localhost:5000/profile?user_id=1" -b cookies.txt
# → 显示 admin 的邮箱、手机、余额 ¥99999  ❌

# 修复后
$ curl -sk "https://localhost:5000/profile?user_id=1" -b cookies.txt
# → 仍显示 alice 自己的信息  ✅
```

### HC-AUTH-03: 任意账户充值

```bash
# 修复前 - 修改隐藏字段 user_id
$ curl -sk -X POST https://localhost:5000/recharge \
  -d "user_id=1&amount=500" -b cookies.txt
# → admin 余额增加  ❌

# 修复后
$ curl -sk -X POST https://localhost:5000/recharge \
  -d "amount=500" -b cookies.txt
# → 只能操作自己的账户  ✅
```

### HC-AUTH-04: 负数充值

```bash
$ curl -sk -X POST https://localhost:5000/recharge \
  -b cookies.txt \
  -d "amount=-99999"
# 修复前 → 余额减少  ❌
# 修复后 → "充值金额必须大于 0"  ✅
```

### HC-AUTH-05: CSRF

```bash
# 不带 CSRF token
$ curl -sk -X POST https://localhost:5000/recharge \
  -b cookies.txt \
  -d "amount=100"
# 修复前 → 充值成功  ❌
# 修复后 → "安全校验失败，请重试"  ✅
```

---

## 4. 修复方案

### 4 层纵深防御架构

```
┌────────────────────────────────────────────────────────────┐
│  Layer 1: 基于 Session 的身份绑定                          │
│  /profile 从 session["username"] 获取用户，忽略 URL 参数   │
├────────────────────────────────────────────────────────────┤
│  Layer 2: 基于 Session 的操作授权                          │
│  /recharge 从 session["username"] 确定目标用户              │
│  表单中移除 user_id 隐藏字段                               │
├────────────────────────────────────────────────────────────┤
│  Layer 3: 输入校验                                         │
│  amount 必须 > 0，拒绝负数、零、非数字                     │
├────────────────────────────────────────────────────────────┤
│  Layer 4: CSRF Token                                       │
│  每个表单携带 CSRF token，POST 时校验                      │
│  Token 使用 secrets.compare_digest 安全比对                │
└────────────────────────────────────────────────────────────┘
```

### 修复细节

#### HC-AUTH-01/02: Profile 路由权限修复

```python
# ❌ 修复前：信任 URL 参数
user_id = request.args.get("user_id")
c.execute("SELECT ... FROM users WHERE id = ?", (user_id,))

# ✅ 修复后：从 session 获取当前用户名
username = session.get("username")
if not username:
    return redirect("/login")
c.execute("SELECT ... FROM users WHERE username = ?", (username,))
```

#### HC-AUTH-03: Recharge 路由对象级授权修复

```python
# ❌ 修复前：信任表单参数
user_id = request.form.get("user_id")
c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))

# ✅ 修复后：从 session 获取当前用户
username = session.get("username")
c.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, username))
```

#### HC-AUTH-04: 金额正负校验

```python
# ✅ 新增校验
if amount <= 0:
    return render_template("profile.html", error="充值金额必须大于 0")
```

#### HC-AUTH-05: CSRF 防护

```python
# CSRF token 生成
import secrets

def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

def validate_csrf_token(token):
    stored = session.get("_csrf_token")
    if not stored or not token:
        return False
    return secrets.compare_digest(stored, token)

# 注入所有模板
@app.context_processor
def inject_csrf():
    return dict(csrf_token=generate_csrf_token())

# 模板中使用
<input type="hidden" name="_csrf_token" value="{{ csrf_token }}">

# POST 时校验
if not validate_csrf_token(csrf_input):
    return render_template("profile.html", error="安全校验失败，请重试")
```

---

## 5. 修复前后代码对比

### /profile 路由

```python
# ═══════════════════════════════════════════════════
# ❌ 修复前 — 25 行，无权限校验
# ═══════════════════════════════════════════════════
@app.route("/profile")
def profile():
    user_id = request.args.get("user_id")
    # 信任 URL 参数 → IDOR
    try:
        user_id = int(user_id)
    except ...
    c.execute("SELECT ... FROM users WHERE id = ?", (user_id,))
    # 无权限校验，可查看任意用户
    return render_template("profile.html", user=user_dict)

# ═══════════════════════════════════════════════════
# ✅ 修复后 — 从 session 获取用户
# ═══════════════════════════════════════════════════
@app.route("/profile")
def profile():
    username = session.get("username")
    if not username:
        return redirect("/login")
    c.execute("SELECT ... FROM users WHERE username = ?", (username,))
    # 仅能查看自己的资料
    return render_template("profile.html", user=user_dict)
```

### /recharge 路由

```python
# ═══════════════════════════════════════════════════
# ❌ 修复前 — 信任表单参数 + 无 CSRF
# ═══════════════════════════════════════════════════
@app.route("/recharge", methods=["POST"])
def recharge():
    user_id = request.form.get("user_id")  # 可被篡改
    amount = request.form.get("amount")
    amount = float(amount)  # 无正负校验
    c.execute("UPDATE ... WHERE id = ?", (amount, user_id))
    return redirect(f"/profile?user_id={user_id}")

# ═══════════════════════════════════════════════════
# ✅ 修复后 — 4 层防御
# ═══════════════════════════════════════════════════
@app.route("/recharge", methods=["POST"])
def recharge():
    username = session.get("username")
    if not username:
        return redirect("/login")

    # Layer 4: CSRF 校验
    if not validate_csrf_token(csrf_input):
        return render_template("profile.html", error="安全校验失败，请重试")

    amount = float(amount)
    # Layer 3: 正数校验
    if amount <= 0:
        return render_template("profile.html", error="充值金额必须大于 0")

    # Layer 1-2: Session 授权
    c.execute("UPDATE ... balance + ? WHERE username = ?", (amount, username))
    return redirect("/profile")
```

---

## 6. 安全测试验证

### 6.1 新增测试用例（9 个）

| 测试用例 | 验证内容 | 结果 |
|---------|---------|------|
| `test_profile_requires_login` | 未登录跳转 | ✅ PASS |
| `test_profile_shows_own_info` | 显示自己的信息 | ✅ PASS |
| `test_profile_ignores_user_id_param` | user_id 参数被忽略 | ✅ PASS |
| `test_recharge_requires_login` | 未登录跳转 | ✅ PASS |
| `test_recharge_without_csrf_fails` | 无 CSRF 拒绝 | ✅ PASS |
| `test_recharge_with_wrong_csrf_fails` | 错误 CSRF 拒绝 | ✅ PASS |
| `test_recharge_negative_amount_fails` | 负数拒绝 | ✅ PASS |
| `test_recharge_zero_amount_fails` | 零元拒绝 | ✅ PASS |
| `test_recharge_legit_succeeds` | 合法充值成功 | ✅ PASS |

### 6.2 手工验证

```bash
# 越权测试
$ curl "https://localhost:5000/profile?user_id=1"  # 登录后
# → 始终显示自己的信息，忽略 user_id 参数

# 负数充值测试
$ curl -X POST https://localhost:5000/recharge -d "amount=-100&_csrf_token=..."
# → "充值金额必须大于 0"

# CSRF 测试
$ curl -X POST https://localhost:5000/recharge -d "amount=100"
# → "安全校验失败，请重试"
```

### 6.3 全量测试结果（42/42 ✅）

```
TestPasswordStorage          ✅ 4/4
TestSecretKeyManagement      ✅ 2/2
TestPasswordPolicy           ✅ 6/6
TestAuthSecurity             ✅ 5/5
TestTransportSecurity        ✅ 4/4
TestInfoLeakage              ✅ 2/2
TestSQLInjection             ✅ 5/5
TestFileUploadSecurity       ✅ 5/5
TestAuthZSecurity            ✅ 9/9  ← 新增
─────────────────────────────────
总计                         ✅ 42/42
```

---

## 7. 长效防御措施

### 开发规范

| 规范 | 要求 |
|------|------|
| ✅ 必须 | 从 session 获取当前用户标识，不信任 URL/表单参数 |
| ✅ 必须 | 金额、数量等数值字段做正负校验 |
| ✅ 必须 | 所有写操作接口实施 CSRF 防护 |
| ✅ 必须 | 确保 CSRF token 使用安全比较 `compare_digest` |
| ✅ 建议 | 充值、转账等资金操作记录审计日志 |

### 运行期防护

| 防御层 | 措施 |
|--------|------|
| 应用层 | Session 身份绑定 + CSRF Token |
| 审计层 | `logger.warning` 记录所有越权/CSRF 尝试 |
| 测试层 | 42 项自动化安全测试覆盖 |

---

*本报告由自动化安全审计工具生成。报告生成时间：2026-07-22T04:40 UTC*
