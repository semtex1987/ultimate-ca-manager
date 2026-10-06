"""Migration 094: HSM custodian roster for SmartCard-HSM (sc-hsm-cloud).

Stores per-custodian connect tokens (encrypted at the application layer) and
share indices. DKEK share bytes are never persisted.

Dual-backend (SQLite + PostgreSQL).
"""
import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True


def _upgrade_sqlite(conn):
    tables = {
        row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    if 'hsm_custodians' in tables:
        logger.info("094: hsm_custodians already present (SQLite)")
        return
    conn.execute("""
        CREATE TABLE hsm_custodians (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_id INTEGER NOT NULL REFERENCES hsm_providers(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id),
            display_name VARCHAR(255) NOT NULL DEFAULT '',
            share_index INTEGER NOT NULL,
            connect_token_enc TEXT NOT NULL,
            auth_public_key TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (provider_id, share_index)
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_hsm_custodians_provider "
        "ON hsm_custodians(provider_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_hsm_custodians_user "
        "ON hsm_custodians(user_id)"
    )
    conn.commit()
    logger.info("094: created hsm_custodians (SQLite)")


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text

    if 'hsm_custodians' in inspect(conn).get_table_names():
        logger.info("094: hsm_custodians already present (PostgreSQL)")
        return
    if 'hsm_providers' not in inspect(conn).get_table_names():
        logger.info("094: no hsm_providers yet; model create_all will add custodians")
        return
    conn.execute(text("""
        CREATE TABLE hsm_custodians (
            id SERIAL PRIMARY KEY,
            provider_id INTEGER NOT NULL REFERENCES hsm_providers(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id),
            display_name VARCHAR(255) NOT NULL DEFAULT '',
            share_index INTEGER NOT NULL,
            connect_token_enc TEXT NOT NULL,
            auth_public_key TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT uq_hsm_custodian_share UNIQUE (provider_id, share_index)
        )
    """))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_hsm_custodians_provider "
        "ON hsm_custodians(provider_id)"
    ))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_hsm_custodians_user "
        "ON hsm_custodians(user_id)"
    ))
    logger.info("094: created hsm_custodians (PostgreSQL)")


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    pass
