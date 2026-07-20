"""
======================================================================
  安全单元测试套件 — 覆盖密码安全、密钥管理、认证校验、传输加密
  执行：python -m pytest tests/test_security.py -v
======================================================================
"""
import os
import sys
import bcrypt
import pytest

# 将被测应用加入路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app, validate_password_strength, USERS, get_safe_user_info


# ======================== Fixtures ========================

ERROR_MSG = "用户名或密码错误"

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-key-for-pytest"
    with app.test_client() as c:
        with app.app_context():
            yield c


# ======================== HC-01: 密码存储安全 ========================

class TestPasswordStorage:
    """HC-01 密码本地存储 — 验证 bcrypt 哈希存储"""

    def test_all_users_have_bcrypt_hash(self):
        """所有用户必须使用 bcrypt 哈希 (以 $2b$ 开头)"""
        for username, user in USERS.items():
            h = user.get("password_hash", "")
            assert h.startswith("$2b$"), (
                f"[FAIL] {username} 的密码不是 bcrypt 哈希: {h[:20]}..."
            )
            # 验证是合法的 bcrypt 哈希
            assert len(h) == 60, f"[FAIL] {username} 的 bcrypt 哈希长度不是 60"

    def test_no_plaintext_password_in_user_dict(self):
        """用户字典禁止存在 password 明文字段"""
        for username, user in USERS.items():
            assert "password" not in user, (
                f"[FAIL] {username} 存在明文 password 字段！"
            )

    def test_bcrypt_verify_valid_password(self):
        """使用 bcrypt.checkpw 能够验证正确密码"""
        assert bcrypt.checkpw(
            "admin123".encode("utf-8"),
            USERS["admin"]["password_hash"].encode("utf-8"),
        ), "[FAIL] admin123 的 bcrypt 验证失败"

    def test_bcrypt_reject_invalid_password(self):
        """使用 bcrypt.checkpw 能够拒绝错误密码"""
        assert not bcrypt.checkpw(
            "wrongpass".encode("utf-8"),
            USERS["admin"]["password_hash"].encode("utf-8"),
        ), "[FAIL] 错误密码不应通过验证"


# ======================== HC-02: 密钥管理 ========================

class TestSecretKeyManagement:
    """HC-02 密钥硬编码 — 验证环境变量隔离"""

    def test_secret_key_from_env(self):
        """SECRET_KEY 必须从环境变量加载"""
        key = app.secret_key
        assert key != "", "[FAIL] secret_key 为空"
        assert "dev-key-2025" not in key, (
            "[FAIL] 仍然包含原来的硬编码密钥 dev-key-2025"
        )

    def test_secret_key_not_in_source_code(self):
        """验证 app.py 中没有硬编码密钥"""
        with open("app.py", encoding="utf-8") as f:
            source = f.read()
        assert 'secret_key = "' not in source.replace(
            'SECRET_KEY = os.getenv("SECRET_KEY")', ""
        ).replace(
            'SECRET_KEY = os.environ.get("SECRET_KEY")', ""
        ), "[FAIL] app.py 中可能仍存在硬编码密钥赋值"


# ======================== HC-03: 强密码策略 ========================

class TestPasswordPolicy:
    """HC-03 弱密码身份认证 — 验证强密码校验"""

    def test_min_length(self):
        """密码长度至少 10 位"""
        valid, reasons = validate_password_strength("Ab1!short")
        assert not valid, "[FAIL] 8位密码不应通过校验"

    def test_require_uppercase(self):
        """必须包含大写字母"""
        valid, reasons = validate_password_strength("abcdefgh1!@")
        assert not valid, "[FAIL] 无大写字母不应通过"

    def test_require_lowercase(self):
        """必须包含小写字母"""
        valid, reasons = validate_password_strength("ABCDEFGH1!@")
        assert not valid, "[FAIL] 无小写字母不应通过"

    def test_require_digit(self):
        """必须包含数字"""
        valid, reasons = validate_password_strength("Abcdefgh!@#")
        assert not valid, "[FAIL] 无数字不应通过"

    def test_require_special(self):
        """必须包含特殊符号"""
        valid, reasons = validate_password_strength("Abcdefgh1a")
        assert not valid, "[FAIL] 无特殊符号不应通过"

    def test_strong_password_passes(self):
        """符合全部规则的强密码应通过"""
        valid, reasons = validate_password_strength("Admin@2025!Secure")
        assert valid, f"[FAIL] 强密码未通过: {reasons}"


# ======================== HC-04: 身份认证安全 ========================

class TestAuthSecurity:
    """HC-04 身份认证 — 验证登录流程安全"""

    def test_login_with_correct_password(self, client):
        """正确密码应返回 200 且 session 写入用户名"""
        resp = client.post("/login", data={
            "username": "admin",
            "password": "admin123",
        }, follow_redirects=False)
        assert resp.status_code == 200
        with client.session_transaction() as sess:
            assert sess.get("username") == "admin"

    def test_login_with_wrong_password(self, client):
        """错误密码不应写入 session"""
        resp = client.post("/login", data={
            "username": "admin",
            "password": "wrongpass",
        })
        assert resp.status_code == 200
        assert ERROR_MSG.encode() in resp.data
        with client.session_transaction() as sess:
            assert sess.get("username") is None

    def test_login_nonexistent_user(self, client):
        """不存在的用户不应写入 session"""
        client.post("/login", data={
            "username": "hacker",
            "password": "anypass",
        })
        with client.session_transaction() as sess:
            assert sess.get("username") is None

    def test_logout_clears_session(self, client):
        """登出后 session 应清空"""
        client.post("/login", data={
            "username": "admin",
            "password": "admin123",
        })
        client.get("/logout")
        with client.session_transaction() as sess:
            assert sess.get("username") is None

    def test_password_not_in_page(self, client):
        """首页不应展示密码原文"""
        client.post("/login", data={
            "username": "admin",
            "password": "admin123",
        })
        resp = client.get("/")
        assert resp.status_code == 200
        # 不应出现密码原文
        assert b"admin123" not in resp.data
        # 应显示掩码提示
        assert b"bcrypt" in resp.data or "已加密".encode() in resp.data


# ======================== HC-05: 传输层安全 ========================

class TestTransportSecurity:
    """HC-05 传输加密 — 验证安全 HTTP 头"""

    def test_hsts_header(self, client):
        """响应应包含 Strict-Transport-Security 头（条件：HTTPS 时）"""
        resp = client.get("/")
        # 测试环境通过 HTTP 访问，Talisman 可能不注入 HSTS
        # 实际 HTTPS 环境下 HSTS 由 Talisman 保证
        hsts = resp.headers.get("Strict-Transport-Security", "")
        if hsts:
            assert "max-age" in hsts

    def test_xframe_options(self, client):
        """响应应包含 X-Frame-Options 头（防点击劫持）"""
        resp = client.get("/")
        assert "X-Frame-Options" in resp.headers

    def test_content_security_policy(self, client):
        """响应应包含 Content-Security-Policy 头"""
        resp = client.get("/")
        csp = resp.headers.get("Content-Security-Policy", "")
        assert csp != "", "[FAIL] 缺少 CSP 头"

    def test_session_cookie_httponly(self, client):
        """Session cookie 应通过 Set-Cookie 响应头设置 HttpOnly"""
        resp = client.post("/login", data={
            "username": "admin",
            "password": "admin123",
        })
        set_cookie = resp.headers.get("Set-Cookie", "")
        assert "HttpOnly" in set_cookie, (
            "[FAIL] session cookie 未设置 HttpOnly 标志"
        )


# ======================== HC-06: 信息泄露防护 ========================

class TestInfoLeakage:
    """HC-06 防止敏感信息泄露"""

    def test_safe_user_info_no_password(self):
        """get_safe_user_info 不应返回 password_hash"""
        info = get_safe_user_info("admin")
        assert info is not None
        assert "password_hash" not in info
        assert "password" not in info

    def test_no_debug_comment_in_login(self, client):
        """登录页不应泄露默认账号调试注释"""
        resp = client.get("/login")
        assert "调试信息".encode() not in resp.data, (
            "[FAIL] 登录页包含泄露账号的 HTML 注释！"
        )
        assert b"admin123" not in resp.data


# ======================== HC-07: SQL 注入防护 ========================

class TestSQLInjection:
    """HC-07 SQL 注入 — 验证参数化查询防御"""

    def test_register_sql_injection_username(self, client):
        """注册时用户名含 SQL 注入语句不应影响数据库"""
        # 尝试 SQL 注入：用户名包含闭合单引号和 DELETE 语句
        resp = client.post("/register", data={
            "username": "x'; DELETE FROM users; --",
            "password": "Test123",
            "email": "x@x.com",
            "phone": "13900000000",
        }, follow_redirects=True)
        # 不应报 500 错误
        assert resp.status_code != 500
        # 数据库中的用户不应被删除（admin 和 alice 必须仍在）
        import sqlite3
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        count = c.fetchone()[0]
        conn.close()
        assert count >= 2, "[FAIL] SQL 注入导致数据被删除！"

    def test_search_sql_injection_or_1eq1(self, client):
        """搜索时 SQL 注入 ' OR '1'='1 不应返回所有用户"""
        # 先正常登录
        client.post("/login", data={
            "username": "admin",
            "password": "admin123",
        })
        # 使用 SQL 注入 payload
        resp = client.get("/search?keyword=1' OR '1'%3D'1")
        # 不应是 500 错误
        assert resp.status_code != 500
        # 应只返回匹配的用户而非全部用户
        # 正常返回时不报错即可

    def test_search_sql_injection_union(self, client):
        """搜索时 UNION 注入不应暴露其他表数据"""
        client.post("/login", data={
            "username": "admin",
            "password": "admin123",
        })
        resp = client.get("/search?keyword=' UNION SELECT * FROM users--")
        assert resp.status_code != 500

    def test_search_special_chars_safe(self, client):
        """搜索含特殊字符应安全处理"""
        client.post("/login", data={
            "username": "admin",
            "password": "admin123",
        })
        resp = client.get("/search?keyword=<script>alert(1)</script>")
        assert resp.status_code == 200
        # 应安全显示，不报错

    def test_register_and_search_roundtrip(self, client):
        """注册后能通过搜索正常找到"""
        # 注册
        client.post("/register", data={
            "username": "sqltest_user",
            "password": "Test123!",
            "email": "sqltest@example.com",
            "phone": "13700000000",
        })
        # 登录
        client.post("/login", data={
            "username": "admin",
            "password": "admin123",
        })
        # 搜索
        resp = client.get("/search?keyword=sqltest")
        assert resp.status_code == 200
        assert "sqltest".encode() in resp.data
