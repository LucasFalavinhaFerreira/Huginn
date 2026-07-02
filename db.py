"""
Muninn — memória do Huginn.

Na mitologia nórdica, Huginn (pensamento) e Muninn (memória) são os dois
corvos de Odin. Huginn investiga; Muninn guarda o que foi aprendido.

Esta camada persiste todas as investigações no Postgres, permitindo
consultar o histórico completo sem precisar rebater nas APIs externas.
"""
import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime

DATABASE_URL = os.getenv("DATABASE_URL")


def get_connection():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL não definida. Configure a connection string do Neon "
            "como variável de ambiente / secret."
        )
    return psycopg2.connect(DATABASE_URL)


def inicializar_banco():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigacoes (
            id SERIAL PRIMARY KEY,
            ioc TEXT NOT NULL,
            tipo TEXT NOT NULL,
            data_investigacao TIMESTAMP NOT NULL,
            veredito TEXT NOT NULL,
            score INTEGER NOT NULL DEFAULT 0,
            detalhes_json TEXT,
            ttps_json TEXT,
            relatorio_html TEXT
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()


def salvar_investigacao(ioc, tipo, veredito, score, detalhes, ttps, relatorio_html):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO investigacoes
                (ioc, tipo, data_investigacao, veredito, score,
                 detalhes_json, ttps_json, relatorio_html)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            ioc, tipo, datetime.now(), veredito, score,
            json.dumps(detalhes, ensure_ascii=False),
            json.dumps(ttps, ensure_ascii=False),
            relatorio_html,
        ))
        investigacao_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
        conn.close()
        return investigacao_id
    except Exception as e:
        print(f"[db] Falha ao salvar investigação de {ioc}: {e}")
        return None


def listar_investigacoes(limite=20):
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, ioc, tipo, data_investigacao, veredito, score
            FROM investigacoes
            ORDER BY data_investigacao DESC
            LIMIT %s
        """, (limite,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Exception as e:
        print(f"[db] Falha ao listar investigações: {e}")
        return []


def buscar_investigacao(investigacao_id):
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT * FROM investigacoes WHERE id = %s
        """, (investigacao_id,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if row:
            row = dict(row)
            row["detalhes_json"] = json.loads(row["detalhes_json"] or "{}")
            row["ttps_json"] = json.loads(row["ttps_json"] or "[]")
        return row
    except Exception as e:
        print(f"[db] Falha ao buscar investigação {investigacao_id}: {e}")
        return None
