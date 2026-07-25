# 🔒 SSTI 模板注入漏洞安全修复报告

> **项目名称：** 用户信息管理平台（Python Flask）
> **项目路径：** `/opt/Class01`
> **报告版本：** v8.0 — SSTI 安全修复版
> **报告日期：** 2026-07-23
> **漏洞编号：** HC-SSTI-01 ~ HC-SSTI-02 (CWE-1336 / CWE-94)

---

## 目录

1. [漏洞概述](#1-漏洞概述)
2. [漏洞详情与风险分析](#2-漏洞详情与风险分析)
3. [漏洞复现过程](#3-漏洞复现过程)
4. [修复方案](#4-修复方案)
5. [修复前后代码对比](#5-修复前后代码对比)
6. [安全测试验证](#6-安全测试验证)
7. [长效防御措施](#7-长效防御措施)
8. [累计安全体系](#8-累计安全体系)

---

## 1. 漏洞概述

| 漏洞编号 | 漏洞类型 | CWE | CVSS 3.1 | 风险等级 |
|---------|---------|-----|----------|---------|
| **HC-SSTI-01** | 欢迎页 SSTI — `render_template_string` + f-string | CWE-1336 | 9.8 | 🔴 Critical |
| **HC-SSTI-02** | 反馈页 SSTI — `render_template_string` + f-string | CWE-1336 | 9.8 | 🔴 Critical |

### 攻击路径总图

```
攻击者
  │
  ├──▶ HC-SSTI-01: /welcome?name={{7*7}}
  │     render_template_string(f"<h1>欢迎你，{name}！</h1>")
  │     → name = "{{7*7}}" → Jinja2 计算为 "49"
  │     └──▶ 模板代码注入执行
  │
  ├──▶ HC-SSTI-01: /welcome?name={{config}}
  │     → 读取 Flask 配置 (含 SECRET_KEY)
  │     └──▶ 密钥泄露 → Session 伪造
  │
  ├──▶ HC-SSTI-01: /welcome?name={{''.__class__.__mro__}}
  │     → 遍历 Python 类继承链
  │     └──▶ RCE: subprocess.Popen 远程命令执行
  │
  └──▶ HC-SSTI-02: /feedback POST name={{config}}&message={{7*7}}
        → 两个字段均可注入
        └──▶ 双入口注入
```

### 攻击链危害

| 攻击阶段 | Payload 示例 | 效果 |
|---------|-------------|------|
| 信息探测 | `{{7*7}}` | ✅ 确认 SSTI 存在 |
| 配置泄露 | `{{config}}` | ❌ SECRET_KEY、数据库密码泄露 |
| Secret Key 窃取 | `{{config.SECRET_KEY}}` | ❌ Session 伪造、任意用户登录 |
| 类链遍历 | `{{''.__class__.__mro__[1].__subclasses__()}}` | ❌ 定位危险类 |
| 远程命令执行 (RCE) | `{{''.__class__.__mro__[1].__subclasses__()[X]('cat /etc/passwd',shell=True,stdout=-1).communicate()}}` | ❌ **服务器沦陷** |

---

## 2. 漏洞详情与风险分析

### 漏洞根因

`render_template_string()` 是 Flask/Werkzeug 的核心函数，它将字符串作为 Jinja2 模板进行解析和渲染。当用户输入通过 **f-string 直接拼入**模板字符串时，用户输入中的 `{{ }}` 语法会被 Jinja2 引擎当成模板代码执行。

### 漏洞原代码

```python
# ❌ 危险模式：f-string 拼接 + render_template_string
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    # name = "{{config.SECRET_KEY}}"
    content = f"<h1>欢迎你，{name}！</h1>"
    #                ↑ 用户输入 {{config.SECRET_KEY}} 被拼入模板
    return render_template_string(content)
    # ↑ Jinja2 引擎解析 → 渲染 {{config.SECRET_KEY}} → 输出密钥
```

### 执行流程

```
┌──────────────────────────────────────────────────────────────────┐
│  请求: /welcome?name={{config.SECRET_KEY}}                       │
│                                                                  │
│  1. name = "{{config.SECRET_KEY}}"                               │
│  2. content = f"<h1>欢迎你，{{config.SECRET_KEY}}！</h1>"        │
│              ↓ (f-string 展开)                                    │
│     "<h1>欢迎你，{{config.SECRET_KEY}}！</h1>"                    │
│                                                                  │
│  3. render_template_string(content)                              │
│              ↓ (Jinja2 解析)                                      │
│     "<h1>欢迎你，dev-key-2025-replace-...！</h1>"                │
│              ↓ (密钥被泄露)                                       │
│  4. 攻击者获取 SECRET_KEY → 伪造任意用户 Session                  │
└──────────────────────────────────────────────────────────────────┘
```

### HC-SSTI-01: 欢迎页 SSTI

**风险分析：**

| 输入 | 渲染输出 | 风险 |
|------|---------|------|
| `张三` | 欢迎你，张三 | ✅ 正常 |
| `{{7*7}}` | 欢迎你，49 | ❌ 表达式执行 |
| `{{config}}` | 欢迎你，&lt;Config {SECRET_KEY: ...}&gt; | ❌ 配置泄露 |
| `{{config.SECRET_KEY}}` | 欢迎你，dev-key-... | ❌ 密钥泄露 |
| `{{''.__class__.__mro__[1].__subclasses__()}}` | Python 类列表 | ❌ 类链攻击 |
| `{{''.__class__.__mro__[2].__subclasses__()[X]('cmd',shell=True)}}` | 命令执行结果 | ❌ **RCE** |

### HC-SSTI-02: 反馈页 SSTI

同样的漏洞存在于 `name` 和 `message` **两个字段**：

```python
content = f"<h2>{name} 的反馈：</h2><p>{message}</p>"
return render_template_string(content)
```

| 字段 | Payload | 效果 |
|------|---------|------|
| `name` | `{{7*7}}` | ✅ 确认注入 |
| `message` | `{{config}}` | ❌ 配置泄露 |
| 双字段 | `name={{7*7}}&message={{config}}` | ❌ 双入口注入 |

---

## 3. 漏洞复现过程

### 基础 SSTI 探测

```bash
$ curl "https://localhost:5000/welcome?name={{7*7}}"
# 修复前 → "欢迎你，49"               ❌
# 修复后 → "欢迎你，{{7*7}}"            ✅ (显示原文)
```

### 配置信息泄露

```bash
$ curl "https://localhost:5000/welcome?name={{config}}"
# 修复前 → 显示 SECRET_KEY、ENV 等配置  ❌
# 修复后 → 显示原文 {{config}}           ✅
```

### Secret Key 窃取

```bash
$ curl "https://localhost:5000/welcome?name={{config.SECRET_KEY}}"
# 修复前 → "dev-key-2025-replace-..."   ❌ 密钥泄露
# 修复后 → "{{config.SECRET_KEY}}"       ✅
```

### 类链 RCE 探测

```bash
$ curl "https://localhost:5000/welcome?name={{''.__class__.__mro__[1].__subclasses__()}}"
# 修复前 → Python 子类列表（含 subprocess.Popen） ❌
# 修复后 → 显示原文                           ✅
```

### 反馈页双字段注入

```bash
$ curl -X POST https://localhost:5000/feedback \
  -d "name={{7*7}}&message={{config}}"
# 修复前 → "49 的反馈：<Config ... SECRET_KEY ...>" ❌
# 修复后 → "{{7*7}} 的反馈：{{config}}"             ✅
```

---

## 4. 修复方案

### 修复原理：模板变量注入替代字符串拼接

将用户输入从 **f-string 插值**（在 Python 层面展开）改为 **Jinja2 模板变量**（在模板引擎层面渲染，自动转义），彻底阻断用户输入被解释为模板代码的路径。

```python
# ❌ 危险：f-string 在 Python 层面展开
content = f"<h1>欢迎你，{name}！</h1>"
#         {{config.SECRET_KEY}} 被 f-string 拼入模板字符串
#         Jinja2 解析 → 执行模板代码

# ✅ 安全：模板变量由 render_template_string 接收
content = "<h1>欢迎你，{{ name }}！</h1>"
#         {{ name }} 是 Jinja2 模板占位符
#         name 值作为数据传入，不被解析为模板代码
render_template_string(content, name=name)
```

### 修复说明

```
┌───────────────────────────────────────────────────────────┐
│  修复前: f-string 展开 → render_template_string           │
│                                                           │
│  name = "{{config.SECRET_KEY}}"                           │
│  f"<h1>{name}</h1>"                                       │
│  → "<h1>{{config.SECRET_KEY}}</h1>"  # Jinja2 解析执行    │
│                                                           │
├───────────────────────────────────────────────────────────┤
│  修复后: 模板变量 → render_template_string                 │
│                                                           │
│  name = "{{config.SECRET_KEY}}"                           │
│  "<h1>{{ name }}</h1>"  # Jinja2 占位符                   │
│  → render_template_string(tpl, name=name)                 │
│  → "<h1>{{config.SECRET_KEY}}</h1>"  # 纯文本展示          │
└───────────────────────────────────────────────────────────┘
```

### 修复后代码

```python
# ── 修复后：模板中仅含 Jinja2 变量占位符 ──
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    if not name:
        return render_template_string(WELCOME_NAV + WELCOME_DEFAULT + WELCOME_FOOTER)
    # 模板使用 {{ name }} 作为占位符
    return render_template_string(WELCOME_NAV + "<h1>欢迎你，{{ name }}！</h1>" + WELCOME_FOOTER,
                                   name=name)  # ← 用户输入作为数据传递


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")
        # 模板使用 {{ name }}, {{ message }} 作为占位符
        return render_template_string(FEEDBACK_NAV + "<h2>{{ name }} 的反馈：</h2><p>{{ message }}</p>" + FEEDBACK_FOOTER,
                                       name=name, message=message)  # ← 用户输入作为数据传递
```

---

## 5. 修复前后代码对比

```python
# ═══════════════════════════════════════════════════════════
# ❌ 修复前 — f-string 拼接（SSTI 漏洞）
# ═══════════════════════════════════════════════════════════
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    content = f"<h1>欢迎你，{name}！</h1>"   # ← name 拼入模板
    return render_template_string(content)    # ← Jinja2 解析

@app.route("/feedback", methods=["POST"])
def feedback():
    name = request.form.get("name", "")
    message = request.form.get("message", "")
    content = f"<h2>{name} 的反馈：</h2><p>{message}</p>"  # ← 双字段拼入
    return render_template_string(content)

# ═══════════════════════════════════════════════════════════
# ✅ 修复后 — 模板变量注入
# ═══════════════════════════════════════════════════════════
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    # 模板使用 {{ name }} 占位符，用户输入作为数据
    return render_template_string(
        WELCOME_NAV + "<h1>欢迎你，{{ name }}！</h1>" + WELCOME_FOOTER,
        name=name  # ← 数据传递，不是代码
    )

@app.route("/feedback", methods=["POST"])
def feedback():
    name = request.form.get("name", "")
    message = request.form.get("message", "")
    # 模板使用 {{ name }} {{ message }} 占位符
    return render_template_string(
        FEEDBACK_NAV + "<h2>{{ name }} 的反馈：</h2><p>{{ message }}</p>" + FEEDBACK_FOOTER,
        name=name, message=message  # ← 数据传递
    )
```

### 关键差异总结

| 维度 | 修复前（f-string） | 修复后（模板变量） |
|------|------------------|------------------|
| 用户输入位置 | 拼入模板字符串 | 作为函数参数传递 |
| Jinja2 是否解析输入 | ✅ 是 | ❌ 否 |
| `{{7*7}}` 渲染结果 | `49` | `{{7*7}}` |
| `{{config.SECRET_KEY}}` 渲染结果 | 密钥明文泄露 | `{{config.SECRET_KEY}}` |
| RCE 风险 | ✅ 存在 | ❌ 已消除 |

---

## 6. 安全测试验证

### 6.1 新增测试用例（8 个）

| 测试用例 | 验证内容 | 结果 |
|---------|---------|------|
| `test_welcome_ssti_expr_not_evaluated` | `{{7*7}}` 不计算为 49 | ✅ PASS |
| `test_welcome_ssti_config_not_leaked` | `{{config}}` 不泄露密钥 | ✅ PASS |
| `test_welcome_ssti_class_chain_blocked` | 类链攻击被隔离 | ✅ PASS |
| `test_feedback_ssti_expr_not_evaluated` | 反馈页 `{{7*7}}` 不执行 | ✅ PASS |
| `test_feedback_ssti_config_not_leaked` | 反馈页 `{{config}}` 不泄露 | ✅ PASS |
| `test_feedback_ssti_both_fields_safe` | 双字段均防止 SSTI | ✅ PASS |
| `test_welcome_normal_function` | 欢迎页正常功能 | ✅ PASS |
| `test_feedback_normal_function` | 反馈页正常功能 | ✅ PASS |

### 6.2 全量测试结果（66/66 ✅）

```
TestPasswordStorage          ✅ 4/4
TestSecretKeyManagement      ✅ 2/2
TestPasswordPolicy           ✅ 6/6
TestAuthSecurity             ✅ 5/5
TestTransportSecurity        ✅ 4/4
TestInfoLeakage              ✅ 2/2
TestSQLInjection             ✅ 5/5
TestFileUploadSecurity       ✅ 5/5
TestAuthZSecurity            ✅ 9/9
TestFileInclusion            ✅ 8/8
TestXssAndCsrfSecurity       ✅ 8/8
TestSSTISecurity             ✅ 8/8  ← 新增
─────────────────────────────────────
总计                         ✅ 66/66
```

---

## 7. 长效防御措施

### 编码规范

| 规范 | 要求 |
|------|------|
| ❌ 禁止 | `render_template_string(f"...{user_input}...")` |
| ✅ 必须 | `render_template_string("...{{ var }}...", var=user_input)` |
| ✅ 必须 | `render_template_string` 与 f-string 不能同时使用 |
| ✅ 建议 | 优先使用 `render_template`（文件模板引擎） |
| ✅ 建议 | 如需 `render_template_string`，禁止动态拼接模板结构 |

### SSTI 防御黄金法则

```
          render_template_string 的使用方式
          │
          ├── 静态模板 + 变量参数 = ✅ 安全
          │    render_template_string("Hello {{ name }}", name=input)
          │
          └── 动态拼接 + f-string   = ❌ 危险
               render_template_string(f"Hello {input}")
               # input 中的 {{ }} 被 Jinja2 解析执行
```

### 运行期防护

| 防御层 | 措施 | 状态 |
|--------|------|------|
| 开发规范 | 禁止 f-string + render_template_string 组合 | ✅ 已修复 |
| 代码审查 | Code Review 检查所有 render_template_string 调用 | ✅ 已执行 |
| 安全测试 | 8 项 SSTI 专项测试 | ✅ 66 项总覆盖 |
| Sandbox | Jinja2 Sandbox 环境（默认启用） | ✅ 存在但非防护核心 |

### 其他 SSTI 防护方案

| 方案 | 说明 | 适用场景 |
|------|------|---------|
| **模板变量法**（本项目采用的） | 用户输入作为参数传递，不拼入模板 | `render_template_string` 场景 |
| Jinja2 Sandbox | 限制危险函数访问（如 `subprocess`） | 仅减少 RCE 危害，不防止信息泄露 |
| 输入过滤 | 过滤 `{{ }}` 等模板语法字符 | 易遗漏，不推荐 |
| 静态模板 | 使用 `.html` 文件 + `render_template` | 最佳实践，推荐 |

---

## 8. 累计安全体系

### 修复历程

| 版本 | 修复内容 | 测试数 | 报告 |
|------|---------|--------|------|
| v2.0 | 密码/密钥/认证/传输/审计 | 23 | SECURITY_REPORT.md |
| v3.0 | SQL 注入 | 28 | SQL_INJECTION_REPORT.md |
| v4.0 | 文件上传 | 33 | FILE_UPLOAD_REPORT.md |
| v5.0 | 越权/CSRF | 42 | AUTH_REPORT.md |
| v6.0 | 文件包含 | 50 | FILE_INCLUSION_REPORT.md |
| v7.0 | XSS/CSRF 增强 | 58 | XSS_CSRF_REPORT.md |
| **v8.0** | **SSTI 模板注入** | **66** | **本报告** |

### 全量安全防护矩阵（66 项测试）

| 攻击类型 | 防护方式 | 测试覆盖 |
|---------|---------|---------|
| SQL 注入 | 参数化查询 | 5 |
| 文件上传 | 扩展名/MIME/PIL/路径/配额 | 5 |
| 文件包含 | 规范化 + 边界校验 | 8 |
| 水平越权 | Session 身份绑定 | 3 |
| CSRF | Token 校验 | 5 |
| XSS | 转义 + SVG 净化 | 3 |
| **SSTI** | **模板变量替代 f-string** | **8** |
| 弱密码 | 复杂度策略 | 6 |
| 密钥泄露 | 环境变量 | 2 |
| 信息泄露 | 脱敏输出 | 2 |
| 传输安全 | HTTPS + CSP + HSTS | 4 |

---

*本报告由自动化安全审计工具生成。报告生成时间：2026-07-23T05:10 UTC*
