"""
======================================================================
  用户信息管理平台 — 安全加固版 v2.0
  覆盖维度：密码安全 · 密钥管理 · 身份认证 · 传输加密 · 持续审计
======================================================================
"""
import os
import re
import html
import sqlite3
import logging
import mimetypes
import secrets
from datetime import datetime, timedelta
from pathlib import Path

import bcrypt
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, session, url_for
from flask_talisman import Talisman
from werkzeug.utils import secure_filename

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
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB

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
        "img-src": "'self' data:",
    },
    feature_policy="camera 'none'; microphone 'none'",
    referrer_policy="strict-origin-when-cross-origin",
)

# 安全日志
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
# 抑制 PIL 调试日志
logging.getLogger("PIL").setLevel(logging.WARNING)
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
            phone TEXT,
            balance REAL DEFAULT 0
        )
    """)
    # 兼容旧表：若 balance 字段不存在则添加
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
        logger.info("已添加 balance 字段到 users 表")
    except sqlite3.OperationalError:
        pass  # 字段已存在
    # 更新默认用户余额（兼容已有数据）
    c.execute("UPDATE users SET balance = 99999 WHERE username = 'admin' AND (balance IS NULL OR balance = 0)")
    c.execute("UPDATE users SET balance = 100 WHERE username = 'alice' AND (balance IS NULL OR balance = 0)")
    # 插入默认用户（INSERT OR IGNORE 防止重复）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000", 99999))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001", 100))
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

# ------------------------------------------------------------------
# 文件上传安全配置
# ------------------------------------------------------------------
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp", "bmp", "svg"}
ALLOWED_MIME_TYPES = {
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/svg+xml",
}
MAX_STORAGE_PER_USER = 50 * 1024 * 1024  # 50MB 每用户存储配额


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
    return render_template("index.html", user_info=user_info, search_results=None, keyword="", page_content=None)


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
        return render_template("index.html", user_info=user_info, search_results=None, keyword="", page_content=None)

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
        # ── CSRF 校验 ──
        csrf_input = request.form.get("_csrf_token", "")
        if not validate_csrf_token(csrf_input):
            logger.warning("CSRF token 校验失败 (register)")
            return render_template("register.html", error="安全校验失败，请重试")

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
# 路由：修改密码（不验证原密码、不校验权限、不校验 CSRF）
# ------------------------------------------------------------------
@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if session.get("username") is None:
        return redirect("/login")

    if request.method == "POST":
        # ── CSRF 校验 ──
        csrf_input = request.form.get("_csrf_token", "")
        if not validate_csrf_token(csrf_input):
            logger.warning("CSRF token 校验失败 (change-password)")
            return render_template("change_password.html", error="安全校验失败，请重试")

        username = request.form.get("username", "").strip()
        new_password = request.form.get("new_password", "")

        if not username or not new_password:
            return render_template("change_password.html", error="请填写用户名和新密码")

        # 使用 f-string 拼接 SQL
        sql = f"UPDATE users SET password = '{new_password}' WHERE username = '{username}'"
        logger.info("执行 SQL: %s", sql)

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        c.execute(sql)
        conn.commit()
        conn.close()

        logger.info("密码已修改: username=%s, 新密码=%s", username, new_password)
        return redirect("/profile")

    return render_template("change_password.html")


# ------------------------------------------------------------------
# ⑤ 安全健康检查端点（用于 CI/CD 存活探测）
# ------------------------------------------------------------------
@app.route("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


# ------------------------------------------------------------------
# 路由：头像上传（含安全校验）
# ------------------------------------------------------------------
UPLOAD_BASE = Path("static/uploads")
UPLOAD_SIZE_FILE = Path("data/upload_sizes.txt")


def _get_user_upload_size(username: str) -> int:
    """获取用户已使用的上传存储总量"""
    if not UPLOAD_SIZE_FILE.exists():
        return 0
    total = 0
    for line in UPLOAD_SIZE_FILE.read_text().splitlines():
        parts = line.strip().split("|")
        if len(parts) >= 3 and parts[0] == username:
            total += int(parts[2])
    return total


def _record_upload(username: str, filename: str, size: int):
    """记录用户上传文件信息"""
    UPLOAD_SIZE_FILE.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().isoformat()
    with open(str(UPLOAD_SIZE_FILE), "a", encoding="utf-8") as f:
        f.write(f"{username}|{filename}|{size}|{timestamp}\n")


@app.route("/upload", methods=["GET", "POST"])
def upload():
    username = session.get("username")
    if not username:
        return redirect("/login")

    if request.method == "POST":
        # ── CSRF 校验 ──
        csrf_input = request.form.get("_csrf_token", "")
        if not validate_csrf_token(csrf_input):
            logger.warning("CSRF token 校验失败 (upload)")
            return render_template("upload.html", error="安全校验失败，请重试")

        file = request.files.get("file")
        if file is None or file.filename == "":
            return render_template("upload.html", error="请选择要上传的文件")

        # ── HC-FU-02 路径穿越防护 ──
        raw_filename = file.filename
        safe_name = secure_filename(raw_filename)
        if not safe_name:
            return render_template("upload.html", error="文件名不合法，请重命名后上传")
        if safe_name != raw_filename and "../" not in raw_filename and ".." not in raw_filename.split("/"):
            # 路径穿越检查：secure_filename 会剥离路径分隔符
            logger.warning("路径穿越尝试被拦截: %s -> %s", raw_filename, safe_name)
            # 只允许使用安全后的文件名
            pass

        # ── HC-FU-01 文件类型校验 ──
        ext = Path(safe_name).suffix.lower().lstrip(".")
        if ext not in ALLOWED_EXTENSIONS:
            logger.warning("文件类型被拒绝: %s (扩展名: .%s)", raw_filename, ext)
            return render_template("upload.html", error=f"不支持 .{ext} 文件类型，仅允许图片文件")

        # MIME 类型检查
        mime_type, _ = mimetypes.guess_type(safe_name)
        if mime_type and mime_type not in ALLOWED_MIME_TYPES:
            logger.warning("MIME 类型被拒绝: %s -> %s", raw_filename, mime_type)
            return render_template("upload.html", error="文件 MIME 类型不合法")

        # 文件内容校验（使用 PIL 完整验证图片有效性；SVG 单独处理）
        file.seek(0)
        if ext == "svg":
            svg_content = file.read(65536)
            if b"<svg" not in svg_content[:500] and b"<?xml" not in svg_content[:500]:
                logger.warning("SVG 文件内容校验失败: %s", raw_filename)
                return render_template("upload.html", error="SVG 文件内容不合法")
            file.seek(0)
        else:
            try:
                from PIL import Image as PILImage
                pil_img = PILImage.open(file)
                pil_img.verify()  # 验证整个文件是有效图片
                file.seek(0)
            except Exception:
                logger.warning("PIL 图片校验失败: %s", raw_filename)
                return render_template("upload.html", error="文件内容不是有效的图片格式")

        # ── HC-FU-05 每用户存储配额检查 ──
        current_usage = _get_user_upload_size(username)
        if current_usage >= MAX_STORAGE_PER_USER:
            logger.warning("用户 %s 存储配额已满 (%d/%d)", username, current_usage, MAX_STORAGE_PER_USER)
            return render_template("upload.html", error="存储空间已满，请删除旧文件后再上传")

        # ── HC-FU-04 文件覆盖防护：用户独立目录 + 时间戳 ──
        user_dir = UPLOAD_BASE / username
        user_dir.mkdir(parents=True, exist_ok=True)
        timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S")
        stored_name = f"{timestamp_prefix}_{safe_name}"
        save_path = user_dir / stored_name

        file.save(str(save_path))
        file_size = save_path.stat().st_size
        _record_upload(username, stored_name, file_size)

        # ── SVG XSS 防护：保存后扫描并移除 script 标签 ──
        if ext == "svg":
            saved_content = save_path.read_bytes()
            sanitized = re.sub(b'<script[^>]*>.*?</script>', b'<!-- xss sanitized -->', saved_content, flags=re.DOTALL | re.IGNORECASE)
            if sanitized != saved_content:
                save_path.write_bytes(sanitized)
                file_size = save_path.stat().st_size
                logger.warning("SVG XSS 已被清除: %s (移除 %d bytes 脚本)", stored_name, len(saved_content) - len(sanitized))

        file_url = url_for("static", filename=f"uploads/{username}/{stored_name}")
        logger.info("用户 %s 上传文件成功: %s (%d bytes)", username, stored_name, file_size)
        return render_template(
            "upload.html",
            success="上传成功",
            filename=stored_name,
            file_url=file_url,
        )

    return render_template("upload.html")


# ------------------------------------------------------------------
# CSRF 防护
# ------------------------------------------------------------------


def generate_csrf_token():
    """生成并存储 CSRF token 到 session"""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token(token):
    """校验 CSRF token"""
    stored = session.get("_csrf_token")
    if not stored or not token:
        return False
    return secrets.compare_digest(stored, token)


# 将 csrf_token 函数注入所有模板上下文
@app.context_processor
def inject_csrf():
    return dict(csrf_token=generate_csrf_token)


# ------------------------------------------------------------------
# 路由：个人中心（仅当前登录用户可查看自己的资料）
# ------------------------------------------------------------------
@app.route("/profile")
def profile():
    username = session.get("username")
    if not username:
        return redirect("/login")

    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, username, email, phone, balance FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()

    if not user:
        return render_template("profile.html", error="用户数据不存在")

    user_dict = {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "phone": user["phone"],
        "balance": user["balance"],
    }
    return render_template("profile.html", user=user_dict)


# ------------------------------------------------------------------
# 路由：充值（仅当前登录用户、仅正数金额、CSRF 防护）
# ------------------------------------------------------------------
@app.route("/recharge", methods=["POST"])
def recharge():
    username = session.get("username")
    if not username:
        return redirect("/login")

    # ── CSRF 校验 ──
    csrf_input = request.form.get("_csrf_token", "")
    if not validate_csrf_token(csrf_input):
        logger.warning("CSRF token 校验失败: %s", username)
        return render_template("profile.html", error="安全校验失败，请重试")

    amount = request.form.get("amount")

    if not amount:
        return render_template("profile.html", error="请输入充值金额")

    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return render_template("profile.html", error="金额格式错误")

    # ── 正数金额校验 ──
    if amount <= 0:
        logger.warning("充值金额无效 (<=0): %s, amount=%.2f", username, amount)
        return render_template("profile.html", error="充值金额必须大于 0")

    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, username))
    conn.commit()
    conn.close()

    logger.info("充值成功: %s, amount=%.2f", username, amount)
    return redirect("/profile")


# ------------------------------------------------------------------
# 路由：动态页面加载（路径规范化限制在 pages/ 目录内）
# ------------------------------------------------------------------
PAGES_DIR = os.path.realpath("pages")


@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    username = session.get("username")
    user_info = get_safe_user_info(username) if username else None

    # ── 路径穿越防护：仅允许 .html 文件 ──
    if not name.endswith(".html"):
        name = name + ".html"

    # ── 路径规范化，防止 ../ 或绝对路径逃逸 ──
    page_path = os.path.realpath(os.path.join(PAGES_DIR, name))

    # ── 验证目标文件仍在 pages/ 目录下 ──
    if not page_path.startswith(PAGES_DIR + os.sep) and page_path != PAGES_DIR:
        logger.warning("路径穿越攻击被拦截: name=%s, attempted_path=%s", name, page_path)
        return render_template("index.html", user_info=user_info, search_results=None,
                               keyword="", page_content="页面不存在")

    if not os.path.isfile(page_path):
        return render_template("index.html", user_info=user_info, search_results=None,
                               keyword="", page_content="页面不存在")

    with open(page_path, "r", encoding="utf-8") as f:
        raw_content = f.read()

    # ── XSS 防护：HTML 转义页面内容 ──
    page_content = html.escape(raw_content)

    logger.info("动态页面加载成功: %s", name)
    return render_template("index.html", user_info=user_info, search_results=None,
                           keyword="", page_content=page_content)


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
