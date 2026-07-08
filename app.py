from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import time
import uuid
import os
import sqlite3

app = Flask(__name__)

# 使用强随机密钥
app.secret_key = secrets.token_hex(32)

# Session Cookie 安全标记 + 过期时间
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600,
    SESSION_COOKIE_NAME='session',
)

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
    token = uuid.uuid4().hex
    session["_csrf_token"] = token
    return token


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
    return render_template("index.html", user=user, search_results=None, search_keyword="")


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
        if token != session.get("_csrf_token", ""):
            return render_template("login.html", error="请求校验失败，请刷新页面后重试", csrf_token=generate_csrf_token())

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if safe_check_password(username, password):
            session.permanent = True
            session["username"] = username
            LOGIN_ATTEMPTS.pop(ip, None)
            user = safe_user(username)
            return render_template("index.html", user=user, search_results=None, search_keyword="")

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
    return render_template("index.html", user=user, search_results=results, search_keyword=keyword)


if __name__ == "__main__":
    init_db()
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "server"
    WSGIRequestHandler.sys_version = ""
    app.run(debug=False, host="0.0.0.0", port=5000, ssl_context="adhoc")
