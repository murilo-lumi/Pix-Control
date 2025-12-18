# ======================================================
# ENV
# ======================================================
from dotenv import load_dotenv
import os
import secrets

load_dotenv()

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

# ======================================================
# APP
# ======================================================
app = Flask(__name__)
app.config["SECRET_KEY"] = FLASK_SECRET_KEY

# Cookies seguros (nível SaaS)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True  # TRUE somente quando estiver em HTTPS (nuvem)
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
# SEGURANÇA PIX
# ======================================================
def validar_assinatura_pix(payload, assinatura):
    calc = hmac.new(
        PIX_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(calc, assinatura or "")

# ======================================================
# ROTAS PÚBLICAS
# ======================================================
@app.route("/")
def index():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    # gera CSRF
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    if request.method == "POST":
        # valida CSRF
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

            return redirect("/gerente" if user[1] == "gerente" else "/caixa")

        return render_template("login.html", erro=True)

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ======================================================
# GERENTE
# ======================================================
@app.route("/gerente")
@login_required
@role_required("gerente")
def gerente():
    hoje = datetime.now().strftime("%Y-%m-%d")
    total, quantidade = resumo_do_dia(hoje)

    return render_template(
        "gerente.html",
        data=hoje,
        total=total,
        quantidade=quantidade
    )


@app.route("/gerente/usuarios")
@login_required
@role_required("gerente")
def gerente_usuarios():
    return render_template(
        "usuarios.html",
        usuarios=listar_usuarios()
    )


@app.route("/gerente/usuarios/criar", methods=["POST"])
@login_required
@role_required("gerente")
def criar_caixa_view():
    # CSRF
    if request.form.get("csrf_token") != session.get("csrf_token"):
        abort(403)

    criar_usuario(
        request.form["username"],
        request.form["senha"],
        "caixa"
    )
    return redirect("/gerente/usuarios")


@app.route("/gerente/usuarios/<int:user_id>/status")
@login_required
@role_required("gerente")
def status_caixa(user_id):
    alterar_status_usuario(
        user_id,
        int(request.args.get("ativo"))
    )
    return redirect("/gerente/usuarios")

# ======================================================
# CAIXA
# ======================================================
@app.route("/caixa")
@login_required
@role_required("caixa")
def caixa():
    return render_template("painel_caixa.html", SOCKETIO_TOKEN=SOCKETIO_TOKEN)

# ======================================================
# WEBHOOK PIX
# ======================================================
@app.route("/webhook/pix", methods=["POST"])
def webhook_pix():
    payload = request.get_data()
    assinatura = request.headers.get("X-Signature")

    if not validar_assinatura_pix(payload, assinatura):
        return jsonify({"error": "assinatura inválida"}), 401

    data = request.json or {}

    salvar_pix(
        data.get("paymentId", "N/A"),
        float(data.get("amount", 0)),
        data.get("status", "CONFIRMADO")
    )

    total, qtd = resumo_do_dia()

    socketio.emit("pix_received", {
        "valor": f"{data.get('amount',0):.2f}",
        "status": "CONFIRMADO",
        "hora": datetime.now().strftime("%H:%M:%S"),
        "total_dia": f"{total:.2f}",
        "quantidade_dia": qtd
    })

    return jsonify({"ok": True})

# ======================================================
# RELATÓRIO PDF • PREMIUM (SEM LOGO)
# ======================================================
@app.route("/relatorio/<data>/pdf")
@login_required
@role_required("gerente")
def relatorio_pdf(data):
    fechamento = buscar_fechamento(data)

    if not fechamento:
        total, qtd = resumo_do_dia(data)
        fechamento = {
            "total": total,
            "quantidade": qtd
        }

    total = fechamento["total"]
    quantidade = fechamento["quantidade"]
    ticket = total / quantidade if quantidade > 0 else 0

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    largura, altura = A4

    # Margens
    x = 50
    y = altura - 60

    # TÍTULO
    c.setFont("Helvetica-Bold", 22)
    c.drawString(x, y, "PIX CONTROL")

    y -= 28
    c.setFont("Helvetica", 12)
    c.drawString(x, y, "Relatório diário de pagamentos")

    y -= 18
    c.setFont("Helvetica", 10)
    c.drawString(x, y, f"Data: {data}")

    # Linha divisória
    y -= 20
    c.setLineWidth(1)
    c.line(x, y, largura - 50, y)

    # MÉTRICAS
    y -= 40
    c.setFont("Helvetica-Bold", 13)
    c.drawString(x, y, "Resumo financeiro")

    y -= 25
    c.setFont("Helvetica", 12)
    c.drawString(x, y, f"Total em PIX:")
    c.drawRightString(largura - 50, y, f"R$ {total:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."))

    y -= 20
    c.drawString(x, y, "Quantidade de transações:")
    c.drawRightString(largura - 50, y, f"{quantidade}")

    y -= 20
    c.drawString(x, y, "Ticket médio:")
    c.drawRightString(largura - 50, y, f"R$ {ticket:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."))

    # Linha final
    y -= 35
    c.setLineWidth(0.5)
    c.line(x, y, largura - 50, y)

    # RODAPÉ
    y -= 25
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(
        x,
        y,
        "Documento gerado automaticamente pelo sistema PIX Control"
    )

    y -= 14
    c.setFont("Helvetica", 9)
    c.drawString(
        x,
        y,
        "PIX Control • Plataforma SaaS de gestão de pagamentos"
    )

    c.showPage()
    c.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"pix_control_relatorio_{data}.pdf",
        mimetype="application/pdf"
    )

# ======================================================
# FECHAMENTO AUTOMÁTICO
# ======================================================
def fechamento_auto():
    while True:
        agora = datetime.now()
        if agora.hour == 23 and agora.minute == 59:
            fechar_dia(agora.strftime("%Y-%m-%d"))
            time.sleep(70)
        time.sleep(30)

# ======================================================
# START
# ======================================================
if __name__ == "__main__":
    Thread(target=fechamento_auto, daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=5005)