"""
core — Núcleo de Ciber-Shield.

Exporta los componentes fundamentales para que los módulos
superiores los importen desde un único punto:

    from core import Config, init_db, get_session, get_logger
    from core.models import Scan, Host, Port, Vulnerability, Finding, Report
"""

from .config   import Config
from .database import init_db, get_session, get_db_session, close_db_session, health_check
from .logger   import get_logger, logger
from .models   import (
    Base,
    Scan, ScanStatus,
    Host,
    Port,
    Vulnerability,
    Finding,
    Report,
    Severity,
)

__all__ = [
    # Config
    "Config",
    # Database
    "init_db", "get_session", "get_db_session",
    "close_db_session", "health_check",
    # Logger
    "get_logger", "logger",
    # Models
    "Base",
    "Scan", "ScanStatus",
    "Host",
    "Port",
    "Vulnerability",
    "Finding",
    "Report",
    "Severity",
]
