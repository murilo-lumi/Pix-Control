import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_NAME = "pix.db"


# =====================
# Conexão
# =====================
def get_connection():
    return sqlite3.connect(DB_NAME, check_same_thread=False)


# =====================
# Inicialização
# =====================
def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # PIX
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pix (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payment_id TEXT UNIQUE,
            valor REAL,
            status TEXT,
            data TEXT,
            hora TEXT
        )
    """)

    # Fechamento
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fechamento_diario (
            data TEXT PRIMARY KEY,
            total REAL,
            quantidade INTEGER,
            fechado_em TEXT
        )
    """)

    # Usuários
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            senha TEXT,
            tipo TEXT,
            ativo INTEGER DEFAULT 1,
            criado_em TEXT
        )
    """)

    # Gerente padrão
    cursor.execute("SELECT COUNT(*) FROM usuarios")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO usuarios (username, senha, tipo, ativo, criado_em)
            VALUES (?, ?, ?, 1, ?)
        """, (
            "gerente",
            generate_password_hash("admin123"),
            "gerente",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

    conn.commit()
    conn.close()


# =====================
# Autenticação
# =====================
def autenticar_usuario(username, senha):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, senha, tipo
        FROM usuarios
        WHERE username = ? AND ativo = 1
    """, (username,))

    user = cursor.fetchone()
    conn.close()

    if not user:
        return None

    if check_password_hash(user[1], senha):
        return user[0], user[2]

    return None


# =====================
# Usuários
# =====================
def listar_usuarios():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, tipo, ativo, criado_em
        FROM usuarios
        ORDER BY criado_em
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def criar_usuario(username, senha, tipo="caixa"):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO usuarios (username, senha, tipo, ativo, criado_em)
        VALUES (?, ?, ?, 1, ?)
    """, (
        username,
        generate_password_hash(senha),
        tipo,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def alterar_status_usuario(user_id, ativo):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET ativo = ? WHERE id = ?", (ativo, user_id))
    conn.commit()
    conn.close()


# =====================
# PIX
# =====================
def salvar_pix(payment_id, valor, status):
    conn = get_connection()
    cursor = conn.cursor()

    agora = datetime.now()

    # evita duplicado
    cursor.execute("""
        INSERT OR IGNORE INTO pix (payment_id, valor, status, data, hora)
        VALUES (?, ?, ?, ?, ?)
    """, (
        payment_id,
        valor,
        status,
        agora.strftime("%Y-%m-%d"),
        agora.strftime("%H:%M:%S")
    ))

    conn.commit()
    conn.close()


def resumo_do_dia(data=None):
    if not data:
        data = datetime.now().strftime("%Y-%m-%d")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT IFNULL(SUM(valor),0), COUNT(*)
        FROM pix
        WHERE data = ?
    """, (data,))

    total, qtd = cursor.fetchone()
    conn.close()
    return float(total), qtd


# =====================
# Fechamento
# =====================
def fechar_dia(data=None):
    if not data:
        data = datetime.now().strftime("%Y-%m-%d")

    total, qtd = resumo_do_dia(data)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO fechamento_diario
        VALUES (?, ?, ?, ?)
    """, (
        data,
        total,
        qtd,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def listar_pix_por_dia(data):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT payment_id, valor, hora
        FROM pix
        WHERE data = ?
        ORDER BY hora
    """, (data,))

    rows = cursor.fetchall()
    conn.close()

    return [
        {"payment_id": r[0], "valor": r[1], "hora": r[2]}
        for r in rows
    ]


def buscar_fechamento(data):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT data, total, quantidade, fechado_em
        FROM fechamento_diario
        WHERE data = ?
    """, (data,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "data": row[0],
        "total": row[1],
        "quantidade": row[2],
        "fechado_em": row[3],
        "pix": listar_pix_por_dia(data)
    }