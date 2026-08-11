"""
core/database.py — Gestión del engine SQLAlchemy y sesiones de base de datos.

Expone:
    init_db()     → Crea el engine, tablas y devuelve el engine.
    get_session() → Context manager para obtener una sesión transaccional.
    db_session    → Sesión scoped para usar en Flask (request-scoped).
"""

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, Engine, event, text
from sqlalchemy.orm import sessionmaker, scoped_session, Session

from .config import Config
from .models import Base


# ── Engine (inicializado en init_db) ──────────────────────────
_engine: Engine | None = None
_SessionFactory: scoped_session | None = None


def init_db(echo: bool | None = None) -> Engine:
    """
    Inicializa el engine de SQLAlchemy y crea todas las tablas.

    Debe llamarse una vez al arrancar la aplicación, antes de
    cualquier operación de base de datos.

    Args:
        echo: Si es True, SQLAlchemy imprime las queries SQL.
              Por defecto usa Config.DEBUG.

    Returns:
        El engine de SQLAlchemy configurado.
    """
    global _engine, _SessionFactory

    Config.ensure_dirs()

    _echo = echo if echo is not None else Config.DEBUG

    _engine = create_engine(
        Config.DATABASE_URL,
        echo=_echo,
        # SQLite necesita check_same_thread=False para Flask
        connect_args={"check_same_thread": False}
        if "sqlite" in Config.DATABASE_URL else {},
    )

    # Activar WAL mode en SQLite para mejor concurrencia
    if "sqlite" in Config.DATABASE_URL:
        @event.listens_for(_engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, _):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    _SessionFactory = scoped_session(
        sessionmaker(bind=_engine, autocommit=False, autoflush=False)
    )

    # Crear todas las tablas definidas en los modelos
    Base.metadata.create_all(_engine)

    return _engine


def get_engine() -> Engine:
    """Devuelve el engine activo. Lanza RuntimeError si no está inicializado."""
    if _engine is None:
        raise RuntimeError(
            "Base de datos no inicializada. Llama a init_db() primero."
        )
    return _engine


def get_session_factory() -> scoped_session:
    """Devuelve la fábrica de sesiones. Lanza RuntimeError si no está inicializada."""
    if _SessionFactory is None:
        raise RuntimeError(
            "Base de datos no inicializada. Llama a init_db() primero."
        )
    return _SessionFactory


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """
    Context manager para obtener una sesión de base de datos transaccional.

    Hace commit automático al salir del bloque si no hay excepciones.
    Hace rollback si se lanza alguna excepción.

    Uso:
        with get_session() as session:
            scan = Scan(name="Test", target="192.168.1.0/24")
            session.add(scan)
            # commit automático al salir del bloque

    Raises:
        RuntimeError: Si la BD no está inicializada.
        Exception: Cualquier excepción de SQLAlchemy (después del rollback).
    """
    factory = get_session_factory()
    session: Session = factory()

    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ── Sesión scoped para Flask ──────────────────────────────────
# En el contexto de Flask, usar db_session directamente en las rutas.
# El teardown_appcontext se encarga de cerrarla al final de cada request.

def get_db_session() -> Session:
    """
    Devuelve la sesión scoped activa.

    En Flask, usar así dentro de una ruta o servicio:
        session = get_db_session()
        scans = session.query(Scan).all()
    """
    return get_session_factory()()


def close_db_session(exception: Exception | None = None) -> None:
    """
    Cierra la sesión scoped. Registrar como teardown en Flask:
        app.teardown_appcontext(close_db_session)
    """
    if _SessionFactory is not None:
        _SessionFactory.remove()


def reset_db() -> None:
    """
    Elimina todas las tablas y las recrea desde cero.
    PELIGROSO: borra todos los datos. Solo para tests y desarrollo.
    """
    engine = get_engine()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)


def health_check() -> dict:
    """
    Comprueba el estado de la conexión a la base de datos.

    Returns:
        dict con status, url (sin contraseña) y número de tablas.
    """
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        table_count = len(Base.metadata.tables)
        return {
            "status":      "ok",
            "url":         Config.DATABASE_URL.split("@")[-1]
                           if "@" in Config.DATABASE_URL
                           else Config.DATABASE_URL,
            "tables":      table_count,
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}
