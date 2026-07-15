from flask import Flask, render_template, request, redirect, session, send_from_directory, abort, g
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import time
import uuid
import os
import sqlite3
from urllib.parse import urlparse
import urllib.request
import urllib.error

app = Flask(__name__)

# 使用强随机密钥
app.secret_key = secrets.token_hex(32)

# Session Cookie 安全标记 + 过期时间
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',  # 升级为 Strict，防止跨站请求携带Cookie
    PERMANENT_SESSION_LIFETIME=3600,
    SESSION_COOKIE_NAME='session',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 最大上传 16MB
)

# CSRF 豁免路由列表（这些路由自行处理CSRF验证或不需要验证）
CSRF_EXEMPT_ROUTES = {
    'login',        # login 路由内部已有CSRF验证逻辑
    'logout',       # GET 请求，仅清除session
    'index',        # GET 请求，仅展示页面
    'search',       # GET 请求，查询操作
    'profile',      # GET 请求，仅展示页面
    'page',         # GET 请求，读取静态页面
    'serve_upload', # GET 请求，获取上传文件
}

# 登录频率限制
LOGIN_ATTEMPTS = {}

# ========== 数据库初始化 ==========
def init_db():
    os.makedirs("data", exist_ok=True)
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
    # 为旧数据库添加 balance 列（如果不存在）
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", generate_password_hash("admin123"), "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", generate_password_hash("alice2025"), "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()
    print("[DB] 数据库初始化完成")

# 密码从环境变量读取
_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "LCh123456*")
_ALICE_PASSWORD = os.environ.get("ALICE_PASSWORD", "Al1ce#2025!")

USERS = {
    "LCH's-website-123456": {
        "username": "LCH's-website-123456",
        "password": generate_password_hash(_ADMIN_PASSWORD),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash(_ALICE_PASSWORD),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


def mask_phone(phone):
    if len(phone) >= 7:
        return phone[:3] + "****" + phone[7:]
    return phone


def mask_email(email):
    if "@" in email:
        name, domain = email.split("@", 1)
        if len(name) > 2:
            name = name[0] + "***" + name[-1]
        else:
            name = name[0] + "***"
        return name + "@" + domain
    return email


def get_db():
    return sqlite3.connect("data/users.db")


def get_user_from_db(username):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT username, password, email, phone FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            "username": row[0],
            "password": row[1],
            "email": row[2] or "",
            "phone": row[3] or "",
            "role": "user",
            "balance": 0,
        }
    return None


def safe_user(username):
    if username in USERS:
        raw = USERS[username]
    else:
        raw = get_user_from_db(username)
    if raw is None:
        return None
    return {
        "username": raw["username"],
        "email": mask_email(raw.get("email", "")),
        "phone": mask_phone(raw.get("phone", "")),
        "role": raw.get("role", "user"),
        "balance": raw.get("balance", 0),
    }


def safe_check_password(username, password):
    user = USERS.get(username)
    if user is None:
        user = get_user_from_db(username)
    if user is None:
        check_password_hash(
            "pbkdf2:sha256:600000$dummy$dummy_dummy_dummy_dummy_dummy_dummy",
            password
        )
        return False
    return check_password_hash(user["password"], password)


def generate_csrf_token():
    """生成CSRF Token并存入Session"""
    token = secrets.token_hex(32)  # 使用加密安全随机数（64字符）
    session["_csrf_token"] = token
    session["_csrf_token_time"] = int(time.time())
    return token


def validate_csrf_token(token):
    """验证CSRF Token有效性"""
    stored_token = session.get("_csrf_token", "")
    if not stored_token or not token:
        return False
    # 使用常量时间比较防止时序攻击
    return secrets.compare_digest(stored_token, token)


def validate_referer_or_origin():
    """验证 Referer/Origin 头，作为CSRF纵深防御"""
    origin = request.headers.get("Origin", "")
    referer = request.headers.get("Referer", "")

    # 如果没有 Origin 和 Referer，对于浏览器POST请求可疑（但允许API客户端）
    if not origin and not referer:
        return True  # 放行（可能是非浏览器客户端），token验证仍是主要防线

    # 解析请求的host
    host = request.host.split(":")[0]  # 去掉端口号

    # 检查 Origin
    if origin:
        try:
            origin_host = urlparse(origin).hostname
            if origin_host and (origin_host == host or origin_host.endswith("." + host)):
                return True
        except Exception:
            pass

    # 检查 Referer
    if referer:
        try:
            referer_host = urlparse(referer).hostname
            if referer_host and (referer_host == host or referer_host.endswith("." + host)):
                return True
        except Exception:
            pass

    return False


@app.before_request
def csrf_protect():
    """
    全局CSRF保护中间件
    对所有 POST/PUT/PATCH/DELETE 请求强制执行CSRF Token验证
    """
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None  # GET/HEAD/OPTIONS 请求不需要CSRF保护

    # 检查是否在豁免列表中
    if request.endpoint in CSRF_EXEMPT_ROUTES:
        return None

    # 第一道防线：Origin/Referer 验证（纵深防御）
    if not validate_referer_or_origin():
        app.logger.warning(f"[CSRF] Origin/Referer校验失败 — {request.url} — Origin: {request.headers.get('Origin')} — Referer: {request.headers.get('Referer')}")
        # 不直接拒绝，继续进行Token验证作为主要防线
        # 但对于高风险操作，可直接拒绝：
        if request.endpoint in ('recharge', 'change_password'):
            abort(403, description="CSRF校验失败：Origin/Referer不匹配")

    # 第二道防线：CSRF Token 验证（主要防线）
    # 优先从表单中获取，其次从自定义请求头获取
    token = request.form.get("_csrf_token", "")
    if not token:
        token = request.headers.get("X-CSRF-Token", "")

    if not validate_csrf_token(token):
        app.logger.warning(f"[CSRF] Token校验失败 — {request.url} — Endpoint: {request.endpoint}")
        # 对于AJAX请求返回JSON，对于普通表单返回403
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.headers.get("Accept") == "application/json":
            return {"error": "CSRF token校验失败，请刷新页面后重试"}, 403
        abort(403, description="CSRF token校验失败，请刷新页面后重试")

    # 第三道防线：Token一次性使用（防止复用）
    # 验证通过后刷新token，防止token重放
    # 注意：此操作在验证成功后进行
    g._csrf_token_refreshed = True


@app.after_request
def refresh_csrf_token(response):
    """在POST请求成功后刷新CSRF Token（一次性使用模式）"""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if getattr(g, '_csrf_token_refreshed', False):
            generate_csrf_token()
    return response


# 全局 CSRF Token 注入到所有模板上下文
@app.context_processor
def inject_csrf_token():
    """确保所有模板都有 csrf_token 可用"""
    token = session.get("_csrf_token", "")
    if not token:
        token = generate_csrf_token()
    return {"csrf_token": token}


# ========== 安全响应头 ==========
@app.after_request
def add_security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com"
    )
    return response


@app.route("/")
def index():
    username = session.get("username")
    user = safe_user(username) if username else None
    return render_template("index.html", user=user, search_results=None, search_keyword="", fetch_result="", fetch_url="")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "127.0.0.1"
        now = time.time()

        if ip in LOGIN_ATTEMPTS:
            attempts, first = LOGIN_ATTEMPTS[ip]
            if now - first > 300:
                LOGIN_ATTEMPTS[ip] = [1, now]
            elif attempts >= 5:
                return render_template("login.html", error="登录尝试过多，请300秒后再试", csrf_token=session.get("_csrf_token"))
            else:
                LOGIN_ATTEMPTS[ip] = [attempts + 1, first]
        else:
            LOGIN_ATTEMPTS[ip] = [1, now]

        token = request.form.get("_csrf_token", "")
        if not validate_csrf_token(token):
            return render_template("login.html", error="请求校验失败，请刷新页面后重试", csrf_token=generate_csrf_token())

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if safe_check_password(username, password):
            session.permanent = True
            session["username"] = username
            LOGIN_ATTEMPTS.pop(ip, None)
            user = safe_user(username)
            return render_template("index.html", user=user, search_results=None, search_keyword="", fetch_result="", fetch_url="")

        return render_template("login.html", error="用户名或密码错误", csrf_token=session.get("_csrf_token"))

    return render_template("login.html", csrf_token=generate_csrf_token())


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        params = (username, generate_password_hash(password), email, phone)
        print(f"[REGISTER SQL] {sql} | params={params}")
        try:
            c.execute(sql, params)
            conn.commit()
            conn.close()
            return redirect("/login?msg=注册成功，请登录")
        except Exception as e:
            conn.close()
            return render_template("register.html", error=f"注册失败：{e}")

    return render_template("register.html")


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
    params = (f"%{keyword}%", f"%{keyword}%")
    print(f"[SEARCH SQL] {sql} | params={params}")
    try:
        c.execute(sql, params)
        results = c.fetchall()
        conn.close()
    except Exception as e:
        conn.close()
        results = []
        print(f"[SEARCH ERROR] {e}")

    username = session.get("username")
    user = safe_user(username) if username else None
    return render_template("index.html", user=user, search_results=results, search_keyword=keyword, fetch_result="", fetch_url="")


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("username"):
        return redirect("/login")
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择文件")

        # 1. 单文件大小校验 (< 2MB)
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)
        if size > 2 * 1024 * 1024:
            return render_template("upload.html", error="文件过大（最大 2MB）")

        # 2. 后缀白名单
        ALLOWED = {"png", "jpg", "jpeg", "gif", "webp"}
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if ext not in ALLOWED:
            return render_template("upload.html", error=f"不允许的文件类型: .{ext}")

        # 3. UUID 安全命名（消除路径穿越）
        safe_name = f"{uuid.uuid4().hex}.{ext}"

        # 4. 保存到非公开目录
        upload_dir = os.path.join("data", "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        file.save(os.path.join(upload_dir, safe_name))

        file_url = f"/file/{safe_name}"
        return render_template("upload.html", success=True, file_url=file_url)
    return render_template("upload.html")


@app.route("/file/<filename>")
def serve_upload(filename):
    if not session.get("username"):
        return redirect("/login")
    upload_dir = os.path.join("data", "uploads")
    return send_from_directory(upload_dir, filename)


@app.route("/profile")
def profile():
    if not session.get("username"):
        return redirect("/login")
    user = _get_profile_user()
    return render_template("profile.html", user=user)


@app.route("/recharge", methods=["POST"])
def recharge():
    if not session.get("username"):
        return redirect("/login")

    # 验证表单用户名与会话用户一致（防会话固定攻击）
    form_username = request.form.get("username", "")
    if form_username != session["username"]:
        abort(403, description="用户身份不一致")

    try:
        amount = float(request.form.get("amount", "0"))
    except (ValueError, TypeError):
        amount = 0

    if amount <= 0:
        return render_template("profile.html", user=_get_profile_user(), error="充值金额必须大于零")
    if amount > 99999:
        return render_template("profile.html", user=_get_profile_user(), error="单次充值金额不能超过 ¥99999")

    username = session["username"]
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, username))
    conn.commit()
    conn.close()
    return redirect("/profile")


@app.route("/page")
def page():
    name = request.args.get("name", "")
    page_content = None
    # 过滤路径穿越字符
    if ".." in name or "/" in name or "\\" in name:
        page_content = "<p style='color:var(--red);'>无效的页面名称</p>"
    else:
        filepath = os.path.join("pages", name)
        safe_base = os.path.abspath("pages")
        if os.path.isfile(filepath):
            # 验证最终路径在 pages/ 目录内
            realpath = os.path.abspath(filepath)
            if realpath.startswith(safe_base):
                with open(filepath, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                page_content = "<p style='color:var(--red);'>访问被拒绝</p>"
        elif os.path.isfile(filepath + ".html"):
            realpath = os.path.abspath(filepath + ".html")
            if realpath.startswith(safe_base):
                with open(filepath + ".html", "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                page_content = "<p style='color:var(--red);'>访问被拒绝</p>"
        else:
            page_content = "<p style='color:var(--red);'>页面不存在</p>"
    username = session.get("username")
    user = safe_user(username) if username else None
    return render_template("index.html", user=user, search_results=None, search_keyword="", page_content=page_content, fetch_result="", fetch_url="")


@app.route("/change-password", methods=["POST"])
def change_password():
    if not session.get("username"):
        return redirect("/login")

    username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    # 验证表单用户名与会话用户一致
    if username != session["username"]:
        abort(403, description="用户身份不一致")

    # 验证两次密码一致
    if new_password != confirm_password:
        return render_template("profile.html", user=_get_profile_user(), error="两次输入的密码不一致")

    # 验证密码强度（至少8位，包含字母和数字）
    if len(new_password) < 8:
        return render_template("profile.html", user=_get_profile_user(), error="密码长度至少8位")
    if not any(c.isalpha() for c in new_password) or not any(c.isdigit() for c in new_password):
        return render_template("profile.html", user=_get_profile_user(), error="密码必须包含字母和数字")

    # 更新 USERS 字典中的密码
    if username in USERS:
        USERS[username]["password"] = generate_password_hash(new_password)
    # 更新 SQLite 数据库中的密码
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET password = ? WHERE username = ?", (generate_password_hash(new_password), username))
    conn.commit()
    conn.close()
    return redirect("/profile")


def _get_profile_user():
    """获取当前登录用户的完整信息（用于profile页面渲染）"""
    if not session.get("username"):
        return None
    username = session["username"]
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, email, phone, balance FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            "id": row[0],
            "username": row[1],
            "email": row[2] or "",
            "phone": row[3] or "",
            "balance": row[4] or 0,
        }
    return None


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    if not session.get("username"):
        return redirect("/login")
    url = request.form.get("url", "")
    result = ""
    # SSRF 防护
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        result = "Error: 仅支持 http/https 协议"
    else:
        hostname = parsed.hostname or ""
        # 拦截内网地址
        import ipaddress
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                result = "Error: 禁止访问内网地址"
        except ValueError:
            # 主机名而非IP，拦截 localhost
            if hostname.lower() in ("localhost", "127.0.0.1", "0.0.0.0"):
                result = "Error: 禁止访问内网地址"
    if not result:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                body = resp.read().decode("utf-8", errors="replace")[:5000]
                result = f"Status: {status}\n\n{body}"
        except Exception as e:
            result = f"Error: {e}"
    username = session.get("username")
    user = safe_user(username) if username else None
    return render_template("index.html", user=user, search_results=None,
                           search_keyword="", fetch_result=result, fetch_url=url)


if __name__ == "__main__":
    init_db()
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "server"
    WSGIRequestHandler.sys_version = ""
    app.run(debug=False, host="0.0.0.0", port=5000, ssl_context="adhoc")
