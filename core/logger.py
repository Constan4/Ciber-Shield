"""
core/logger.py — Sistema de logging centralizado para Ciber-Shield.

Configura dos handlers:
    1. Consola → output enriquecido con Rich (colores, timestamps)
    2. Archivo → log rotativo en logs/ciber_shield.log

Exporta:
    get_logger(name)  → Logger para un módulo específico
    logger            → Logger raíz de la aplicación
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import Config


# ══════════════════════════════════════════════════════════════
# FORMATEADORES
# ══════════════════════════════════════════════════════════════

class _ConsoleFormatter(logging.Formatter):
    """Formateador con colores ANSI para la consola."""

    COLORS = {
        "DEBUG":    "\033[90m",   # Gris
        "INFO":     "\033[96m",   # Cyan
        "WARNING":  "\033[93m",   # Amarillo
        "ERROR":    "\033[91m",   # Rojo
        "CRITICAL": "\033[95m",   # Magenta
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        ts    = self.formatTime(record, "%H:%M:%S")
        level = f"{color}{record.levelname:<8}{self.RESET}"
        name  = f"{self.BOLD}{record.name}{self.RESET}"
        msg   = record.getMessage()

        # Incluir info de excepción si existe
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)

        return f"  {ts}  {level}  {name} — {msg}"


class _FileFormatter(logging.Formatter):
    """Formateador limpio para el archivo de log (sin colores ANSI)."""

    def format(self, record: logging.LogRecord) -> str:
        ts    = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        msg   = record.getMessage()
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)
        return f"{ts} [{record.levelname:<8}] {record.name} — {msg}"


# ══════════════════════════════════════════════════════════════
# SETUP
# ══════════════════════════════════════════════════════════════

def _setup_root_logger() -> logging.Logger:
    """Configura el logger raíz de Ciber-Shield."""
    Config.ensure_dirs()

    root = logging.getLogger("ciber_shield")
    root.setLevel(logging.DEBUG)

    # Evitar duplicar handlers si se llama varias veces
    if root.handlers:
        return root

    # ── Handler de consola ─────────────────────────────────────
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if Config.DEBUG else logging.INFO)
    console_handler.setFormatter(_ConsoleFormatter())
    root.addHandler(console_handler)

    # ── Handler de archivo rotativo ────────────────────────────
    log_file = Config.LOG_DIR / "ciber_shield.log"
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,  # 5 MB por archivo
        backupCount=3,              # Mantener 3 archivos históricos
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(_FileFormatter())
    root.addHandler(file_handler)

    # Silenciar loggers ruidosos de dependencias
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if Config.DEBUG else logging.WARNING
    )

    return root


def get_logger(name: str) -> logging.Logger:
    """
    Obtiene un logger hijo para un módulo específico.

    Args:
        name: Nombre del módulo. Se recomienda usar __name__.
              Si empieza por "ciber_shield." se queda como está.
              Si no, se prefija con "ciber_shield.".

    Returns:
        Logger configurado con los handlers del logger raíz.

    Uso:
        from core.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Módulo inicializado")
    """
    _setup_root_logger()

    if not name.startswith("ciber_shield"):
        # Normalizar el nombre: core.config → ciber_shield.core.config
        name = f"ciber_shield.{name.lstrip('.')}"

    return logging.getLogger(name)


# ── Logger raíz exportado ─────────────────────────────────────
logger = get_logger("ciber_shield")
