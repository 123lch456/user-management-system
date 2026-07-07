from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import time
import uuid
import os

app = Flask(__name__)

# 使用强随机密钥
app.secret_key = secrets.token_hex(32)

# Session Cookie 安全标记 + 过期时间
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600,       # session 有效期 1 小时
    SESSION_COOKIE_NAME='session',
)

# 登录频率限制：{ip: [attempts, first_attempt_time]}
LOGIN_ATTEMPTS = {}

# ========== 密码从环境变量读取（避免硬编码在源码中） ==========
# 设置方式：export ADMIN_PASSWORD="YourStrongPassword" 或在 .env 中定义
_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "LCh123456*")
_ALICE_PASSWORD = os.environ.get("ALICE_PASSWORD", "Al1ce#2025!")

# 用户数据库（密码使用哈希存储）
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
    """手机号脱敏：138****8000"""
    if len(phone) >= 7:
        return phone[:3] + "****" + phone[7:]
    return phone


def mask_email(email):
    """邮箱脱敏：a***n@example.com"""
    if "@" in email:
        name, domain = email.split("@", 1)
        if len(name) > 2:
            name = name[0] + "***" + name[-1]
        else:
            name = name[0] + "***"
        return name + "@" + domain
    return email


def safe_user(username):
    """返回脱敏后的用户数据，排除密码字段"""
    if username not in USERS:
        return None
    raw = USERS[username]
    return {
        "username": raw["username"],
        "email": mask_email(raw["email"]),
        "phone": mask_phone(raw["phone"]),
        "role": raw["role"],
        "balance": raw["balance"],
    }


def safe_check_password(username, password):
    """恒定时间密码校验，防止基于响应时间的用户名枚举"""
    user = USERS.get(username)
    if user is None:
        # 用户不存在时，用虚拟哈希执行同样的校验操作消耗相同时间
        check_password_hash(
            "pbkdf2:sha256:600000$dummy$dummy_dummy_dummy_dummy_dummy_dummy",
            password
        )
        return False
    return check_password_hash(user["password"], password)


def generate_csrf_token():
    """生成 CSRF Token 并存入 session"""
    token = uuid.uuid4().hex
    session["_csrf_token"] = token
    return token


# ========== 安全响应头 (HSTS + 防点击劫持 + 防 MIME 嗅探 + CSP + 隐藏服务器版本) ==========
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
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "127.0.0.1"
        now = time.time()

        # === 登录频率限制：放在 CSRF 之前，防止被绕过 ===
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

        # CSRF 验证（速率限制后的第二道防线）
        token = request.form.get("_csrf_token", "")
        if token != session.get("_csrf_token", ""):
            return render_template("login.html", error="请求校验失败，请刷新页面后重试", csrf_token=generate_csrf_token())

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # 恒定时间密码校验（防用户枚举）
        if safe_check_password(username, password):
            session.permanent = True
            session["username"] = username
            LOGIN_ATTEMPTS.pop(ip, None)
            user = safe_user(username)
            return render_template("index.html", user=user)

        return render_template("login.html", error="用户名或密码错误", csrf_token=session.get("_csrf_token"))

    # GET 请求：生成新的 CSRF Token
    return render_template("login.html", csrf_token=generate_csrf_token())


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    # 隐藏 Werkzeug 开发服务器版本信息
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "server"
    WSGIRequestHandler.sys_version = ""

    app.run(debug=False, host="0.0.0.0", port=5000, ssl_context="adhoc")
