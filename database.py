import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_NAME = "pix.db"


# ======================================================
# CONEXÃO
# ======================================================
def get_connection():
    return sqlite3.connect(DB_NAME, check_same_thread=False)


# ======================================================
# INIT DB (SaaS READY)
# ======================================================
def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # =====================
    # PLANOS
    # =====================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS planos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            preco REAL,
            max_usuarios INTEGER,
            recursos TEXT
        )
    """)

    # =====================
    # EMPRESAS (TENANTS)
    # =====================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS empresas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            plano_id INTEGER,
            ativa INTEGER DEFAULT 1,
            criada_em TEXT,
            FOREIGN KEY (plano_id) REFERENCES planos(id)
        )
    """)

    # =====================
    # USUÁRIOS
    # =====================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            senha TEXT,
            tipo TEXT,
            ativo INTEGER DEFAULT 1,
            empresa_id INTEGER,
            criado_por INTEGER,
            criado_em TEXT,
            FOREIGN KEY (empresa_id) REFERENCES empresas(id)
        )
    """)

    # =====================
    # PIX
    # =====================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pix (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payment_id TEXT UNIQUE,
            valor REAL,
            status TEXT,
            data TEXT,
            hora TEXT,
            empresa_id INTEGER,
            FOREIGN KEY (empresa_id) REFERENCES empresas(id)
        )
    """)

    # =====================
    # FECHAMENTO DIÁRIO
    # =====================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fechamento_diario (
            data TEXT,
            empresa_id INTEGER,
            total REAL,
            quantidade INTEGER,
            fechado_em TEXT,
            PRIMARY KEY (data, empresa_id)
        )
    """)

    # ======================================================
    # DADOS PADRÃO (NÃO QUEBRA O SISTEMA ATUAL)
    # ======================================================

    # PLANO PROFISSIONAL
    cursor.execute("SELECT COUNT(*) FROM planos")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO planos (nome, preco, max_usuarios, recursos)
            VALUES (?, ?, ?, ?)
        """, (
            "Profissional",
            199.00,
            10,
            "PIX em tempo real, Relatórios, Múltiplos caixas"
        ))

    # EMPRESA PADRÃO
    cursor.execute("SELECT COUNT(*) FROM empresas")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO empresas (nome, plano_id, ativa, criada_em)
            VALUES (?, ?, 1, ?)
        """, (
            "Empresa Padrão",
            1,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

    # GERENTE PADRÃO
    cursor.execute("SELECT COUNT(*) FROM usuarios")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO usuarios (username, senha, tipo, ativo, empresa_id, criado_em)
            VALUES (?, ?, ?, 1, ?, ?)
        """, (
            "gerente",
            generate_password_hash("admin123"),
            "gerente",
            1,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

    conn.commit()
    conn.close()


# ======================================================
# AUTENTICAÇÃO
# ======================================================
def autenticar_usuario(username, senha):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, senha, tipo, empresa_id
        FROM usuarios
        WHERE username = ? AND ativo = 1
    """, (username,))

    user = cursor.fetchone()
    conn.close()

    if not user:
        return None

    if check_password_hash(user[1], senha):
        return user[0], user[2], user[3]  # id, tipo, empresa_id

    return None


# ======================================================
# USUÁRIOS
# ======================================================
def listar_usuarios(empresa_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, username, tipo, ativo, criado_em
        FROM usuarios
        WHERE empresa_id = ?
        ORDER BY criado_em
    """, (empresa_id,))

    rows = cursor.fetchall()
    conn.close()
    return rows


def criar_usuario(username, senha, tipo, empresa_id, criado_por=None):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO usuarios (username, senha, tipo, ativo, empresa_id, criado_por, criado_em)
        VALUES (?, ?, ?, 1, ?, ?, ?)
    """, (
        username,
        generate_password_hash(senha),
        tipo,
        empresa_id,
        criado_por,
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


# ======================================================
# PIX
# ======================================================
def salvar_pix(payment_id, valor, status, empresa_id):
    conn = get_connection()
    cursor = conn.cursor()

    agora = datetime.now()

    cursor.execute("""
        INSERT OR IGNORE INTO pix
        (payment_id, valor, status, data, hora, empresa_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        payment_id,
        valor,
        status,
        agora.strftime("%Y-%m-%d"),
        agora.strftime("%H:%M:%S"),
        empresa_id
    ))

    conn.commit()
    conn.close()


def resumo_do_dia(data, empresa_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT IFNULL(SUM(valor),0), COUNT(*)
        FROM pix
        WHERE data = ? AND empresa_id = ?
    """, (data, empresa_id))

    total, qtd = cursor.fetchone()
    conn.close()
    return float(total), qtd


# ======================================================
# FECHAMENTO
# ======================================================
def fechar_dia(data, empresa_id):
    total, qtd = resumo_do_dia(data, empresa_id)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO fechamento_diario
        (data, empresa_id, total, quantidade, fechado_em)
        VALUES (?, ?, ?, ?, ?)
    """, (
        data,
        empresa_id,
        total,
        qtd,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def buscar_fechamento(data, empresa_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT total, quantidade, fechado_em
        FROM fechamento_diario
        WHERE data = ? AND empresa_id = ?
    """, (data, empresa_id))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "total": row[0],
        "quantidade": row[1],
        "fechado_em": row[2]
    }