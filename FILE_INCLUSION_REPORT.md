# 🔒 文件包含漏洞安全修复报告

> **项目名称：** 用户信息管理平台（Python Flask）
> **项目路径：** `/opt/Class01`
> **报告版本：** v6.0 — 文件包含安全修复版
> **报告日期：** 2026-07-23
> **漏洞编号：** HC-FI-01 ~ HC-FI-04 (CWE-22 / CWE-98)

---

## 目录

1. [漏洞概述](#1-漏洞概述)
2. [漏洞详情与风险分析](#2-漏洞详情与风险分析)
3. [漏洞复现过程](#3-漏洞复现过程)
4. [修复方案](#4-修复方案)
5. [修复前后代码对比](#5-修复前后代码对比)
6. [安全测试验证](#6-安全测试验证)
7. [长效防御措施](#7-长效防御措施)
8. [累计安全修复总览](#8-累计安全修复总览)

---

## 1. 漏洞概述

| 漏洞编号 | 漏洞类型 | CWE | CVSS 3.1 | 风险等级 |
|---------|---------|-----|----------|---------|
| **HC-FI-01** | 路径穿越导致任意文件读取 | CWE-22 | 8.6 | 🔴 High |
| **HC-FI-02** | 绝对路径绕过限制 | CWE-22 | 8.6 | 🔴 High |
| **HC-FI-03** | 敏感文件泄露（源码/数据库） | CWE-200 | 7.5 | 🔴 High |
| **HC-FI-04** | 无文件类型限制（任意扩展名） | CWE-98 | 6.5 | 🟡 Medium |

### 攻击路径总图

```
攻击者
  │
  ├──▶ HC-FI-01: /page?name=../../etc/passwd
  │     os.path.join("pages", "../../etc/passwd")
  │     → pages/../../etc/passwd → /etc/passwd
  │     └──▶ 读取系统密码文件
  │
  ├──▶ HC-FI-02: /page?name=/etc/passwd
  │     os.path.join("pages", "/etc/passwd")
  │     → /etc/passwd（os.path.join 丢弃前缀）
  │     └──▶ 绕过 pages/ 前缀限制
  │
  ├──▶ HC-FI-03: /page?name=../app.py
  │     → 读取应用源码（泄露 SECRET_KEY/数据库密码）
  │     /page?name=../data/users.db
  │     → 下载完整数据库（含所有明文密码）
  │     └──▶ 敏感数据大规模泄露
  │
  └──▶ HC-FI-04: /page?name=../data/users.db
      无后缀名限制，可读取任意扩展名文件
       └──▶ 任意文件下载
```

---

## 2. 漏洞详情与风险分析

### HC-FI-01: 路径穿越导致任意文件读取 (CWE-22)

**漏洞原代码：**

```python
name = request.args.get("name", "")
page_path = os.path.join("pages", name)      # ← 直接拼接
if os.path.isfile(page_path):                 # ← 无路径校验
    with open(page_path, "r") as f:
        page_content = f.read()               # ← 读取任意文件
```

**根因分析：** `os.path.join("pages", "../../etc/passwd")` 返回 `pages/../../etc/passwd`，Python 的 `open()` 自动解析 `../`，导致读取 `/etc/passwd`。

### HC-FI-02: 绝对路径绕过 (CWE-22)

**根因分析：** `os.path.join()` 的特殊行为：如果某个组件是绝对路径（以 `/` 开头），它会丢弃之前所有的组件。因此 `os.path.join("pages", "/etc/passwd")` 直接返回 `/etc/passwd`，完全绕过目录限制。

### HC-FI-03: 敏感文件泄露 (CWE-200)

| 攻击 payload | 泄露内容 | 危害 |
|-------------|---------|------|
| `../app.py` | Flask 应用源码 | SECRET_KEY 泄露、业务逻辑泄露 |
| `../data/users.db` | SQLite 数据库文件 | 全部用户密码明文泄露 |
| `../.env` | 环境变量配置文件 | 密钥、数据库密码泄露 |
| `../certs/key.pem` | TLS 私钥 | HTTPS 加密被破解 |

### HC-FI-04: 无文件类型限制 (CWE-98)

**漏洞原代码：** 代码先尝试直接读取 `name`，如果不存在再尝试 `name + ".html"`。这意味着：

```python
# name 可以是任意扩展名
/page?name=../data/users.db      # → 直接命中，读取 .db 文件
/page?name=../.env               # → 直接命中，读取 .env 配置文件
/page?name=../requirements.txt    # → 直接命中，读取 .txt 文件
```

---

## 3. 漏洞复现过程

### HC-FI-01/02: 读取 /etc/passwd

```bash
# 修复前 — 路径穿越成功 ❌
$ curl -sk "https://localhost:5000/page?name=../../etc/passwd"
# → 显示 root:x:0:0:root:/root:/bin/bash ...

# 修复前 — 绝对路径绕过成功 ❌
$ curl -sk "https://localhost:5000/page?name=/etc/passwd"
# → 显示 root:x:0:0:root:/root:/bin/bash ...

# 修复后 — 被拦截 ✅
$ curl -sk "https://localhost:5000/page?name=../../etc/passwd"
# → "页面不存在"
```

### HC-FI-03: 读取应用源码

```bash
$ curl -sk "https://localhost:5000/page?name=../app.py"
# 修复前 → 显示完整 app.py 源码 ❌
# 修复后 → "页面不存在" ✅
```

### HC-FI-03: 下载数据库

```bash
$ curl -sk "https://localhost:5000/page?name=../data/users.db" -o users.db
# 修复前 → 下载完整数据库，admin123/alice2025 等密码明文泄露 ❌
# 修复后 → "页面不存在" ✅
```

---

## 4. 修复方案

### 3 层纵深防御架构

```
┌────────────────────────────────────────────────────────────┐
│  Layer 1: 路径规范化 (os.path.realpath)                     │
│  将 user input 拼接后的路径解析为绝对路径                   │
│  消除 ../ 和符号链接的影响                                  │
├────────────────────────────────────────────────────────────┤
│  Layer 2: 目录边界校验 (startswith)                         │
│  验证规范化后的路径以 PAGES_DIR + os.sep 开头               │
│  任何逃逸到 pages/ 外的路径均被拒绝                        │
├────────────────────────────────────────────────────────────┤
│  Layer 3: 扩展名白名单 (.html)                              │
│  仅允许 .html 后缀文件                                      │
│  拒绝 .py/.db/.env/.pem/.txt 等敏感扩展名                  │
└────────────────────────────────────────────────────────────┘
```

### 修复后核心代码

```python
PAGES_DIR = os.path.realpath("pages")  # 获取 pages/ 真实绝对路径

@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")

    # Layer 3: 仅允许 .html 文件
    if not name.endswith(".html"):
        name = name + ".html"

    # Layer 1: 路径规范化
    page_path = os.path.realpath(os.path.join(PAGES_DIR, name))

    # Layer 2: 目录边界校验
    if not page_path.startswith(PAGES_DIR + os.sep) and page_path != PAGES_DIR:
        logger.warning("路径穿越攻击被拦截: %s", name)
        return render_template(..., page_content="页面不存在")

    if not os.path.isfile(page_path):
        return render_template(..., page_content="页面不存在")

    with open(page_path, "r", encoding="utf-8") as f:
        page_content = f.read()
    return render_template(..., page_content=page_content)
```

### 防护原理图解

```
用户输入: ../../etc/passwd
                  │
                  ▼
os.path.join("pages", "../../etc/passwd")
                  │
                  ▼
      "pages/../../etc/passwd"
                  │
                  ▼
   os.path.realpath → "/etc/passwd"
                  │
                  ▼
   startswith("/real/path/to/pages/") ?
                  │
           ┌──────┴──────┐
           ▼              ▼
         YES             NO
      ⬇ 允许读取      ⬇ 拒绝
                     "页面不存在"
```

---

## 5. 修复前后代码对比

```python
# ═══════════════════════════════════════════════════════
# ❌ 修复前 — 无任何防护
# ═══════════════════════════════════════════════════════
@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    page_path = os.path.join("pages", name)

    # 尝试直接读
    if os.path.isfile(page_path):
        with open(page_path, "r") as f:
            page_content = f.read()
    else:
        # 尝试 .html 后缀
        page_path_html = page_path + ".html"
        if os.path.isfile(page_path_html):
            with open(page_path_html, "r") as f:
                page_content = f.read()
        else:
            page_content = "页面不存在"

    return render_template("index.html", page_content=page_content)


# ═══════════════════════════════════════════════════════
# ✅ 修复后 — 3 层防御
# ═══════════════════════════════════════════════════════
PAGES_DIR = os.path.realpath("pages")  # 绝对路径锚点

@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")

    # Layer 3: 仅 .html
    if not name.endswith(".html"):
        name = name + ".html"

    # Layer 1: 规范化
    page_path = os.path.realpath(os.path.join(PAGES_DIR, name))

    # Layer 2: 边界检查
    if not page_path.startswith(PAGES_DIR + os.sep):
        return render_template(..., page_content="页面不存在")

    if not os.path.isfile(page_path):
        return render_template(..., page_content="页面不存在")

    with open(page_path, "r") as f:
        page_content = f.read()
    return render_template(..., page_content=page_content)
```

---

## 6. 安全测试验证

### 6.1 新增测试用例（8 个）

| 测试用例 | 验证内容 | 结果 |
|---------|---------|------|
| `test_legit_help_page` | 合法 `help` 页面正常加载 | ✅ PASS |
| `test_path_traversal_etc_passwd` | `../../etc/passwd` 被拦截 | ✅ PASS |
| `test_absolute_path_passwd` | `/etc/passwd` 绝对路径被拦截 | ✅ PASS |
| `test_path_traversal_source_code` | `../app.py` 读取源码被拦截 | ✅ PASS |
| `test_path_traversal_database` | `../data/users.db` 读取被拦截 | ✅ PASS |
| `test_encoded_path_traversal` | `%2e%2e%2f` URL 编码穿越被拦截 | ✅ PASS |
| `test_empty_name` | 空 name 显示"页面不存在" | ✅ PASS |
| `test_nonexistent_page` | 不存在的页面显示"页面不存在" | ✅ PASS |

### 6.2 手工验证

```bash
# 合法页面正常加载
$ curl -sk "https://localhost:5000/page?name=help" -b cookies.txt
# → 显示帮助中心 ✅

# 路径穿越被拦截
$ curl -sk "https://localhost:5000/page?name=../../etc/passwd" -b cookies.txt
# → "页面不存在" ✅

# 绝对路径被拦截
$ curl -sk "https://localhost:5000/page?name=/etc/passwd" -b cookies.txt
# → "页面不存在" ✅

# 源码读取被拦截
$ curl -sk "https://localhost:5000/page?name=../app.py" -b cookies.txt
# → "页面不存在" ✅
```

### 6.3 全量测试结果（50/50 ✅）

```
TestPasswordStorage          ✅ 4/4   bcrypt 哈希存储
TestSecretKeyManagement      ✅ 2/2   密钥环境变量隔离
TestPasswordPolicy           ✅ 6/6   强密码校验
TestAuthSecurity             ✅ 5/5   登录认证安全
TestTransportSecurity        ✅ 4/4   HTTPS + 安全头
TestInfoLeakage              ✅ 2/2   信息泄露防护
TestSQLInjection             ✅ 5/5   SQL 注入防御
TestFileUploadSecurity       ✅ 5/5   文件上传防御
TestAuthZSecurity            ✅ 9/9   权限安全
TestFileInclusion            ✅ 8/8   文件包含防御 ← 新增
──────────────────────────────────────────
总计                         ✅ 50/50
```

---

## 7. 长效防御措施

### 编码规范

| 规范 | 要求 |
|------|------|
| ✅ 必须 | 文件读取操作使用 `os.path.realpath` 规范化路径 |
| ✅ 必须 | 校验规范化后的路径在预期目录内 |
| ✅ 必须 | 限制可读取的文件扩展名 |
| ✅ 建议 | 使用白名单配置页面名称（而非动态路径拼接） |

### 动态页面加载安全原则

```
危险做法: /page?name={user_input} → open("pages/" + user_input)
安全做法: /page/{page_name} → 白名单映射 {"help": "help.html"}
更安全:   页面内容存储在数据库中，按 key 读取
```

### 运行期防护

| 防御层 | 措施 |
|--------|------|
| 应用层 | `os.path.realpath` + `startswith` 双校验 |
| 审计层 | `logger.warning` 记录所有路径穿越尝试 |
| 测试层 | 8 项文件包含专项测试 |

---

## 8. 累计安全修复总览

### 项目历程

| 版本 | 修复内容 | 测试用例 | 报告 |
|------|---------|---------|------|
| v2.0 | 密码安全 + 密钥管理 + 身份认证 + 传输加密 + 持续审计 | 23 | SECURITY_REPORT.md |
| v3.0 | SQL 注入防御 | 28 (+5) | SQL_INJECTION_REPORT.md |
| v4.0 | 文件上传安全 | 33 (+5) | FILE_UPLOAD_REPORT.md |
| v5.0 | 权限安全 + CSRF | 42 (+9) | AUTH_REPORT.md |
| **v6.0** | **文件包含防御** | **50 (+8)** | **本报告** |

### OWASP Top 10:2021 覆盖

| 序号 | 类别 | 状态 |
|------|------|------|
| A01 | Broken Access Control | ✅ Auth v5.0 |
| A02 | Cryptographic Failures | ✅ Secret Key v2.0 |
| A03 | Injection (SQL) | ✅ v3.0 |
| A04 | Insecure Design | ✅ 密码策略 v2.0 |
| A05 | Security Misconfiguration | ✅ Secret Key v2.0 |
| A06 | Vulnerable Components | ✅ CI/CD v2.0 |
| A07 | Identification/Auth Failures | ✅ 登录安全 v2.0 |
| A08 | Software/Data Integrity | ✅ 文件上传 v4.0 |
| A09 | Security Logging Failures | ✅ 审计日志 v2.0 |
| **A05:2021** | **Injection (Path Traversal)** | **✅ v6.0 本报告** |

### 项目文件结构

```
/opt/Class01/
├── app.py                # v6.0 — 全功能安全加固
├── pages/help.html       # 帮助中心
├── templates/            # 模板文件
├── static/               # 静态资源
├── tests/test_security.py # 50 项安全测试
├── scripts/check.sh      # 安全检查脚本
├── SECURITY_REPORT.md    # v2.0 安全报告
├── SQL_INJECTION_REPORT.md  # v3.0 SQL 注入报告
├── FILE_UPLOAD_REPORT.md    # v4.0 上传安全报告
├── AUTH_REPORT.md           # v5.0 权限安全报告
└── 本报告                   # v6.0 文件包含报告
```

---

*本报告由自动化安全审计工具生成。报告生成时间：2026-07-23T04:45 UTC*
