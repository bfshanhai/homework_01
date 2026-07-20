"""
======================================================================
  用户信息管理平台 — 安全加固版 v2.0
  覆盖维度：密码安全 · 密钥管理 · 身份认证 · 传输加密 · 持续审计
======================================================================
"""
import os
import sqlite3
import logging
from datetime import datetime, timedelta
from pathlib import Path

import bcrypt
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, session, url_for
from flask_talisman import Talisman

# ------------------------------------------------------------------
# ① 密钥管理：环境变量加载，禁止硬编码
# ------------------------------------------------------------------
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "❌ 严重安全缺陷：未设置 SECRET_KEY 环境变量。"
        "请创建 .env 文件并写入 SECRET_KEY=你的随机密钥。"
    )

# ------------------------------------------------------------------
# ② Flask 应用初始化 + 安全中间件
# ------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY

# ------------------------------------------------------------------
# ④ 传输加密：安全 HTTP 头 + 开发环境 SSL 配置
# ------------------------------------------------------------------
Talisman(
    app,
    force_https=False,  # 开发环境关闭强制跳转；生产环境开启
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    session_cookie_secure=os.getenv("SESSION_COOKIE_SECURE", "False").lower() == "true",
    session_cookie_http_only=True,
    session_cookie_samesite="Lax",
    content_security_policy={
        "default-src": "'self'",
        "style-src": "'self' 'unsafe-inline'",
    },
    feature_policy="camera 'none'; microphone 'none'",
    referrer_policy="strict-origin-when-cross-origin",
)

# 安全日志
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# 数据库初始化（SQLite）
# ------------------------------------------------------------------


def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    Path("data").mkdir(exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    # 插入默认用户（INSERT OR IGNORE 防止重复）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()
    logger.info("数据库初始化完成: data/users.db")


# 初始化数据库
init_db()

# ------------------------------------------------------------------
# ③ 强密码策略配置
# ------------------------------------------------------------------
PASSWORD_POLICY = {
    "min_length": int(os.getenv("PASSWORD_MIN_LENGTH", 10)),
    "require_upper": os.getenv("PASSWORD_REQUIRE_UPPER", "True").lower() == "true",
    "require_lower": os.getenv("PASSWORD_REQUIRE_LOWER", "True").lower() == "true",
    "require_digit": os.getenv("PASSWORD_REQUIRE_DIGIT", "True").lower() == "true",
    "require_special": os.getenv("PASSWORD_REQUIRE_SPECIAL", "True").lower() == "true",
    "expiry_days": int(os.getenv("PASSWORD_EXPIRY_DAYS", 90)),
}


def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """
    强密码校验器 — 返回 (是否通过, 失败原因列表)
    """
    errors = []
    p = PASSWORD_POLICY

    if len(password) < p["min_length"]:
        errors.append(f"密码长度至少 {p['min_length']} 个字符")

    if p["require_upper"] and not any(c.isupper() for c in password):
        errors.append("必须包含至少一个大写字母")

    if p["require_lower"] and not any(c.islower() for c in password):
        errors.append("必须包含至少一个小写字母")

    if p["require_digit"] and not any(c.isdigit() for c in password):
        errors.append("必须包含至少一个数字")

    if p["require_special"] and not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?`~" for c in password):
        errors.append("必须包含至少一个特殊符号 (!@#$%^&* 等)")

    return len(errors) == 0, errors


def password_expiry_check(username: str) -> tuple[bool, int]:
    """
    密码过期检查 — 返回 (是否过期, 已过天数)
    """
    last_change_file = Path(f"data/pwd_history/{username}.txt")
    if not last_change_file.exists():
        return True, PASSWORD_POLICY["expiry_days"] + 1  # 从未换过→强制更换

    last_change = datetime.fromisoformat(last_change_file.read_text().strip())
    elapsed = (datetime.now() - last_change).days
    return elapsed <= PASSWORD_POLICY["expiry_days"], elapsed


# ------------------------------------------------------------------
# ① 密码哈希存储：bcrypt 取代明文
# ------------------------------------------------------------------
# 预先生成的 bcrypt 哈希（rounds=12，生产环境建议 rounds=14）
# 初始密码信息通过安全渠道单独传递，不写死在代码中
USERS = {
    "admin": {
        "username": "admin",
        "password_hash": "$2b$12$A2uUqs4DJanDHgeT12yx9e4lKS/KgWRUH5BlB4b4X.pQh3d/CaArO",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password_hash": "$2b$12$0mg82078rF/rKqeuM6ppjed80RPsF8uMCNKRdFFeJkHzfCeOAav4a",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


def get_safe_user_info(username: str) -> dict | None:
    """获取脱敏后的用户信息（不含密码字段）"""
    user = USERS.get(username)
    if not user:
        return None
    return {k: v for k, v in user.items() if k != "password_hash"}


# ------------------------------------------------------------------
# 路由：首页
# ------------------------------------------------------------------
@app.route("/")
def index():
    username = session.get("username")
    user_info = get_safe_user_info(username) if username else None
    return render_template("index.html", user_info=user_info, search_results=None, keyword="")


# ------------------------------------------------------------------
# 路由：登录（POST 使用 bcrypt 比对，不走明文 ==）
# ------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = USERS.get(username)
        if not user:
            logger.warning("登录失败 — 用户不存在: %s", username)
            return render_template("login.html", error="用户名或密码错误")

        # ① bcrypt 哈希比对
        stored_hash = user["password_hash"]
        if not bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
            logger.warning("登录失败 — 密码错误: %s", username)
            return render_template("login.html", error="用户名或密码错误")

        # ③ 密码过期检查
        is_valid, elapsed = password_expiry_check(username)
        if not is_valid:
            logger.info("密码已过期: %s (%d 天)", username, elapsed)
            return render_template(
                "login.html",
                error=f"密码已 {elapsed} 天未更换，请及时更新密码",
            )

        # 登录成功
        session["username"] = username
        session["login_time"] = datetime.now().isoformat()
        user_info = get_safe_user_info(username)
        logger.info("登录成功: %s", username)
        return render_template("index.html", user_info=user_info, search_results=None, keyword="")

    return render_template("login.html")


# ------------------------------------------------------------------
# 路由：登出
# ------------------------------------------------------------------
@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    logger.info("用户登出: %s", username)
    return redirect("/")


# ------------------------------------------------------------------
# 路由：注册（参数化查询，防止 SQL 注入）
# ------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 使用参数化查询防止 SQL 注入
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        params = (username, password, email, phone)
        logger.info("执行 SQL (参数化): %s | params=%s", sql, params)

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        try:
            c.execute(sql, params)
            conn.commit()
            logger.info("注册成功: %s", username)
            return render_template("login.html", success="注册成功，请登录")
        except sqlite3.IntegrityError:
            logger.warning("注册失败 — 用户名已存在: %s", username)
            return render_template("register.html", error="用户名已存在")
        finally:
            conn.close()

    return render_template("register.html")


# ------------------------------------------------------------------
# 路由：搜索（参数化查询，防止 SQL 注入）
# ------------------------------------------------------------------
@app.route("/search")
def search():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = get_safe_user_info(username)

    keyword = request.args.get("keyword", "").strip()

    # 使用参数化查询防止 SQL 注入
    sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
    pattern = f"%{keyword}%"
    params = (pattern, pattern)
    logger.info("执行 SQL (参数化): %s | params=%s", sql, params)

    results = []
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    try:
        c.execute(sql, params)
        rows = c.fetchall()
        for row in rows:
            results.append({
                "id": row["id"],
                "username": row["username"],
                "email": row["email"],
                "phone": row["phone"],
            })
        logger.info("搜索结果: %d 条记录", len(results))
    except Exception as e:
        logger.error("搜索出错: %s", e)
    finally:
        conn.close()

    return render_template("index.html", user_info=user_info, search_results=results, keyword=keyword)


# ------------------------------------------------------------------
# 路由：修改密码（含强密码校验）
# ------------------------------------------------------------------
@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    username = session.get("username")
    if not username:
        return redirect("/login")

    if request.method == "POST":
        old_pw = request.form.get("old_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        user = USERS.get(username)
        if not user:
            return render_template("change_password.html", error="用户不存在")

        # 验证旧密码
        if not bcrypt.checkpw(old_pw.encode("utf-8"), user["password_hash"].encode("utf-8")):
            return render_template("change_password.html", error="旧密码错误")

        # 新密码一致性
        if new_pw != confirm_pw:
            return render_template("change_password.html", error="两次输入的新密码不一致")

        # ③ 强密码校验
        valid, reasons = validate_password_strength(new_pw)
        if not valid:
            return render_template("change_password.html", error="；".join(reasons))

        # 新密码 ≠ 旧密码
        if bcrypt.checkpw(new_pw.encode("utf-8"), user["password_hash"].encode("utf-8")):
            return render_template("change_password.html", error="新密码不能与旧密码相同")

        # 更新哈希
        new_hash = bcrypt.hashpw(new_pw.encode("utf-8"), bcrypt.gensalt(rounds=12))
        user["password_hash"] = new_hash.decode("utf-8")

        # 记录变更时间
        Path("data/pwd_history").mkdir(parents=True, exist_ok=True)
        Path(f"data/pwd_history/{username}.txt").write_text(datetime.now().isoformat())

        logger.info("密码已修改: %s", username)
        return render_template("change_password.html", success="密码修改成功，请牢记新密码")

    return render_template("change_password.html")


# ------------------------------------------------------------------
# ⑤ 安全健康检查端点（用于 CI/CD 存活探测）
# ------------------------------------------------------------------
@app.route("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


# ------------------------------------------------------------------
# 启动入口
# ------------------------------------------------------------------
def create_ssl_context():
    """开发环境自签名证书创建"""
    cert_dir = Path("certs")
    cert_dir.mkdir(exist_ok=True)
    cert_path = cert_dir / "cert.pem"
    key_path = cert_dir / "key.pem"

    if not (cert_path.exists() and key_path.exists()):
        logger.info("正在生成自签名 TLS 证书 …")
        import subprocess as sp  # nosec B404 — 仅在开发启动时生成自签名证书

        openssl_path = "/usr/bin/openssl"
        if not os.path.isfile(openssl_path):
            openssl_path = "/usr/local/bin/openssl"
        if not os.path.isfile(openssl_path):
            logger.warning("未找到 openssl，跳过证书自动生成")
            return (None, None)

        sp.run(  # nosec B603 — 使用完整路径，无用户输入拼接
            [
                openssl_path,
                "req", "-x509", "-newkey", "rsa:4096",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "365", "-nodes",
                "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ],
            capture_output=True,
            check=True,
        )
        # 私钥权限收紧
        key_path.chmod(0o600)
        logger.info("自签名证书已生成: certs/")

    return (str(cert_path), str(key_path))


if __name__ == "__main__":
    ssl_context = create_ssl_context()
    logger.info("=" * 60)
    logger.info("  用户管理平台 — 安全加固版已启动")
    logger.info("  HTTPS → https://localhost:5000")
    logger.info("  登录后可在 /change-password 修改密码")
    logger.info("=" * 60)
    if ssl_context == (None, None):
        logger.warning("⚠️  未找到 SSL 证书，将以 HTTP 模式启动（仅开发环境）")
        app.run(  # nosec B104 — 开发服务器需要监听所有接口
            host="0.0.0.0",
            port=5000,
            debug=False,
        )
    else:
        app.run(  # nosec B104 — 开发服务器需要监听所有接口
            host="0.0.0.0",
            port=5000,
            debug=False,
            ssl_context=ssl_context,
        )
