# ======================================================
# ENV
# ======================================================
from dotenv import load_dotenv
import os
import secrets

load_dotenv()

FLASK_ENV = os.getenv("FLASK_ENV", "development")
IS_PROD = FLASK_ENV == "production"

FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
PIX_WEBHOOK_SECRET = os.getenv("PIX_WEBHOOK_SECRET")
SOCKETIO_TOKEN = os.getenv("SOCKETIO_TOKEN")

if not FLASK_SECRET_KEY or not PIX_WEBHOOK_SECRET or not SOCKETIO_TOKEN:
    raise RuntimeError("Variáveis de ambiente não configuradas")

# ======================================================
# IMPORTS
# ======================================================
import hmac
import hashlib
import time
import io
import sqlite3
from datetime import datetime
from threading import Thread
from functools import wraps
from collections import defaultdict

from flask import (
    Flask, render_template, request, jsonify,
    send_file, redirect, session, abort
)
from flask_socketio import SocketIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from database import (
    init_db, salvar_pix, resumo_do_dia, fechar_dia,
    buscar_fechamento, autenticar_usuario,
    listar_usuarios, criar_usuario, alterar_status_usuario
)

from logs import log_event

# ======================================================
# RATE LIMIT
# ======================================================
login_attempts = defaultdict(list)
webhook_hits = defaultdict(list)

def rate_limit_login(ip, max_attempts=5, window=300):
    now = time.time()
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < window]
    if len(login_attempts[ip]) >= max_attempts:
        return False
    login_attempts[ip].append(now)
    return True

def rate_limit_webhook(ip, max_hits=30, window=60):
    now = time.time()
    webhook_hits[ip] = [t for t in webhook_hits[ip] if now - t < window]
    if len(webhook_hits[ip]) >= max_hits:
        return False
    webhook_hits[ip].append(now)
    return True

# ======================================================
# APP
# ======================================================
app = Flask(__name__)
app.config["SECRET_KEY"] = FLASK_SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PROD
)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
init_db()

# ======================================================
# HEADERS DE SEGURANÇA
# ======================================================
@app.after_request
def security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

    if IS_PROD:
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

    return resp

# ======================================================
# DECORATORS
# ======================================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if session.get("tipo") != role:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ======================================================
# LOGIN
# ======================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    if request.method == "POST":
        ip = request.remote_addr

        if not rate_limit_login(ip):
            log_event("login_rate_limit", ip=ip)
            abort(429)

        if request.form.get("csrf_token") != session.get("csrf_token"):
            abort(403)

        user = autenticar_usuario(
            request.form.get("usuario"),
            request.form.get("senha")
        )

        if user:
            session.clear()
            session["user_id"] = user[0]
            session["tipo"] = user[1]
            session["csrf_token"] = secrets.token_hex(16)

            log_event("login_sucesso", user=user[0], ip=ip)
            return redirect("/gerente" if user[1] == "gerente" else "/caixa")

        log_event("login_falha", user=request.form.get("usuario"), ip=ip)
        return render_template("login.html", erro=True)

    return render_template("login.html")

# ======================================================
# WEBHOOK PIX
# ======================================================
@app.route("/webhook/pix", methods=["POST"])
def webhook_pix():
    ip = request.remote_addr

    if not rate_limit_webhook(ip):
        log_event("webhook_rate_limit", ip=ip)
        abort(429)

    payload = request.get_data()
    assinatura = request.headers.get("X-Signature")

    if not hmac.compare_digest(
        hmac.new(PIX_WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest(),
        assinatura or ""
    ):
        log_event("webhook_assinatura_invalida", ip=ip)
        abort(401)

    data = request.json or {}
    salvar_pix(
        data.get("paymentId", "N/A"),
        float(data.get("amount", 0)),
        data.get("status", "CONFIRMADO")
    )

    log_event("webhook_pix_confirmado", ip=ip, extra=data.get("amount"))
    return jsonify({"ok": True})