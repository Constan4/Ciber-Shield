"""
tests/conftest.py — Fixtures de pytest compartidas.

Configura una base de datos SQLite en memoria para los tests,
aislada completamente del entorno de desarrollo.
"""

import os
import pytest

# Sobrescribir la URL de BD ANTES de importar nada de core
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["DEBUG"]        = "false"
os.environ["NVD_API_KEY"]  = ""


from core.config   import Config
from core.database import init_db, reset_db, get_session
from core.models   import Scan, Host, Port, ScanStatus


@pytest.fixture(scope="session")
def db_engine():
    """
    Inicializa la BD en memoria una sola vez por sesión de tests.
    Más rápido que inicializarla en cada test.
    """
    Config.DATABASE_URL = "sqlite:///:memory:"
    engine = init_db(echo=False)
    yield engine


@pytest.fixture(autouse=True)
def clean_db(db_engine):
    """
    Limpia todas las tablas antes de cada test para garantizar aislamiento.
    Se aplica automáticamente a todos los tests.
    """
    reset_db()
    yield
    # No hace falta limpiar después — el siguiente test lo hará


@pytest.fixture
def sample_scan():
    """Crea un Scan de ejemplo en la BD y lo devuelve."""
    with get_session() as session:
        scan = Scan(
            name       = "Test Auditoría",
            target     = "192.168.1.0/24",
            port_range = "1-1024",
            status     = ScanStatus.COMPLETED,
            risk_score = 7.5,
            total_hosts = 2,
            total_open_ports = 5,
            total_vulns = 3,
        )
        session.add(scan)
        session.flush()
        scan_id = scan.id
    return scan_id


@pytest.fixture
def sample_host(sample_scan):
    """Crea un Host de ejemplo asociado al scan de muestra."""
    with get_session() as session:
        host = Host(
            scan_id    = sample_scan,
            ip         = "192.168.1.41",
            hostname   = "DESKTOP-01O917C",
            os         = "Windows 11 21H2",
            os_confidence = 90,
            status     = "up",
            risk_score = 8.5,
            open_ports = 3,
        )
        session.add(host)
        session.flush()
        host_id = host.id
    return host_id
