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
    init_db,
    salvar_pix,
    resumo_do_dia,
    fechar_dia,
    buscar_fechamento,
    autenticar_usuario,
    listar_usuarios,
    criar_usuario,
    alterar_status_usuario
)

# ======================================================
# LOGS (SAFE)
# ======================================================
try:
    from logs import log_event
except Exception:
    def log_event(*args, **kwargs):
        pass

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

socketio = SocketIO(app, async_mode="threading")
init_db()

# ======================================================
# CSRF
# ======================================================
@app.context_processor
def inject_csrf():
    return dict(csrf_token=session.get("csrf_token"))

# ======================================================
# SECURITY HEADERS
# ======================================================
@app.after_request
def security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin"
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

def empresa_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "empresa_id" not in session:
            abort(403)
        return f(*args, **kwargs)
    return wrapper

# ======================================================
# ROTAS
# ======================================================
@app.route("/")
def index():
    return redirect("/login")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

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
            session["empresa_id"] = user[2]
            session["csrf_token"] = secrets.token_hex(16)

            log_event("login_sucesso", user=user[0], ip=ip)
            return redirect("/gerente" if user[1] == "gerente" else "/caixa")

        log_event("login_falha", user=request.form.get("usuario"), ip=ip)
        return render_template("login.html", erro=True)

    return render_template("login.html")

# ======================================================
# GERENTE
# ======================================================
@app.route("/gerente")
@login_required
@role_required("gerente")
@empresa_required
def gerente():
    hoje = datetime.now().strftime("%Y-%m-%d")
    total, quantidade = resumo_do_dia(hoje, session["empresa_id"])
    return render_template("gerente.html", data=hoje, total=total, quantidade=quantidade)

@app.route("/gerente/usuarios")
@login_required
@role_required("gerente")
@empresa_required
def gerente_usuarios():
    return render_template(
        "usuarios.html",
        usuarios=listar_usuarios(session["empresa_id"])
    )

@app.route("/gerente/usuarios/criar", methods=["POST"])
@login_required
@role_required("gerente")
@empresa_required
def criar_caixa_view():
    if request.form.get("csrf_token") != session.get("csrf_token"):
        abort(403)

    criar_usuario(
        request.form["username"],
        request.form["senha"],
        "caixa",
        session["empresa_id"]
    )
    return redirect("/gerente/usuarios")

# ======================================================
# CAIXA
# ======================================================
@app.route("/caixa")
@login_required
@role_required("caixa")
@empresa_required
def caixa():
    return render_template("painel_caixa.html", SOCKETIO_TOKEN=SOCKETIO_TOKEN)

# ======================================================
# WEBHOOK PIX
# ======================================================
@app.route("/webhook/pix", methods=["POST"])
def webhook_pix():
    ip = request.remote_addr

    if not rate_limit_webhook(ip):
        abort(429)

    payload = request.get_data()
    assinatura = request.headers.get("X-Signature")

    calc = hmac.new(
        PIX_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(calc, assinatura or ""):
        abort(401)

    data = request.json or {}
    salvar_pix(
        data.get("paymentId", "N/A"),
        float(data.get("amount", 0)),
        data.get("status", "CONFIRMADO"),
        1  # empresa padrão para webhook externo
    )

    return jsonify({"ok": True})

# ======================================================
# RELATÓRIO PDF
# ======================================================
@app.route("/relatorio/<data>/pdf")
@login_required
@role_required("gerente")
@empresa_required
def relatorio_pdf(data):
    fechamento = buscar_fechamento(data, session["empresa_id"]) or {}
    total = fechamento.get("total", 0)
    quantidade = fechamento.get("quantidade", 0)

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    c.setFont("Helvetica-Bold", 22)
    c.drawString(50, 800, "PIX CONTROL")
    c.drawString(50, 760, f"Total: R$ {total:.2f}")
    c.drawString(50, 740, f"Quantidade: {quantidade}")
    c.showPage()
    c.save()
    buffer.seek(0)

    return send_file(buffer, as_attachment=True,
                     download_name=f"relatorio_{data}.pdf",
                     mimetype="application/pdf")

# ======================================================
# FECHAMENTO AUTO
# ======================================================
def fechamento_auto():
    while True:
        agora = datetime.now()
        if agora.hour == 23 and agora.minute == 59:
            fechar_dia(agora.strftime("%Y-%m-%d"), 1)
            time.sleep(70)
        time.sleep(30)

# ======================================================
# START
# ======================================================
if __name__ == "__main__":
    Thread(target=fechamento_auto, daemon=True).start()
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)