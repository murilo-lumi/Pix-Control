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
# MIGRAÇÕES (SEGURAS)
# ======================================================
def migrar_usuarios_empresa():
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN empresa_id INTEGER DEFAULT 1")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    conn.close()

def garantir_empresa_padrao():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET empresa_id = 1 WHERE empresa_id IS NULL")
    conn.commit()
    conn.close()

# ======================================================
# INIT DB (SAAS READY)
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
    # EMPRESAS
    # =====================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS empresas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            plano_id INTEGER,
            ativa INTEGER DEFAULT 1,
            criada_em TEXT
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
            criado_em TEXT
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
            empresa_id INTEGER
        )
    """)

    # =====================
    # FECHAMENTO
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

    # =====================
    # DADOS PADRÃO
    # =====================
    cursor.execute("SELECT COUNT(*) FROM planos")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO planos (nome, preco, max_usuarios, recursos)
            VALUES (?, ?, ?, ?)
        """, (
            "Profissional",
            199.00,
            10,
            "PIX em tempo real, Relatórios"
        ))

    cursor.execute("SELECT COUNT(*) FROM empresas")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO empresas (nome, plano_id, ativa, criada_em)
            VALUES (?, 1, 1, ?)
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),))

    cursor.execute("SELECT COUNT(*) FROM usuarios")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO usuarios (username, senha, tipo, ativo, empresa_id, criado_em)
            VALUES (?, ?, ?, 1, 1, ?)
        """, (
            "gerente",
            generate_password_hash("admin123"),
            "gerente",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

    conn.commit()
    conn.close()

    # MIGRAÇÕES
    migrar_usuarios_empresa()
    garantir_empresa_padrao()

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

    if user and check_password_hash(user[1], senha):
        return user[0], user[2], user[3]

    return None