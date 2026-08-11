"""
core/config.py — Gestión centralizada de configuración.

Lee las variables de entorno desde el archivo .env y las expone
como atributos de clase para uso en toda la aplicación.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Cargar .env desde la raíz del proyecto
_BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(_BASE_DIR / ".env")


class Config:
    """
    Configuración global de Ciber-Shield.

    Todas las variables de entorno se centralizan aquí.
    Si una variable no está definida en .env se usa el valor por defecto.
    """

    # ── Rutas ───────────────────────────────────────────────────
    BASE_DIR:    Path = _BASE_DIR
    DATA_DIR:    Path = _BASE_DIR / "data"
    LOG_DIR:     Path = _BASE_DIR / "logs"
    REPORTS_DIR: Path = _BASE_DIR / Path(os.getenv("REPORTS_DIR", "reports"))

    # ── Aplicación ──────────────────────────────────────────────
    APP_NAME:   str  = os.getenv("APP_NAME", "Ciber-Shield")
    VERSION:    str  = "1.0.0"
    DEBUG:      bool = os.getenv("DEBUG", "false").lower() == "true"
    SECRET_KEY: str  = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")

    # ── Base de datos ───────────────────────────────────────────
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{_BASE_DIR / 'data' / 'ciber_shield.db'}"
    )

    # ── NVD API ─────────────────────────────────────────────────
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_RESULTS_PER_PAGE: int = 20

    # ── Scanner ─────────────────────────────────────────────────
    SCANNER_TIMEOUT:     float = float(os.getenv("SCANNER_TIMEOUT", "1"))
    SCANNER_MAX_THREADS: int   = int(os.getenv("SCANNER_MAX_THREADS", "150"))
    DEFAULT_PORT_RANGE:  str   = os.getenv("DEFAULT_PORT_RANGE", "1-1024")

    # ── Flask / Web ─────────────────────────────────────────────
    FLASK_HOST: str = os.getenv("FLASK_HOST", "0.0.0.0")
    FLASK_PORT: int = int(os.getenv("FLASK_PORT", "5000"))

    @classmethod
    def ensure_dirs(cls) -> None:
        """Crea los directorios necesarios si no existen."""
        for directory in [cls.DATA_DIR, cls.LOG_DIR, cls.REPORTS_DIR]:
            directory.mkdir(parents=True, exist_ok=True)

    @classmethod
    def validate(cls) -> list[str]:
        """
        Valida la configuración y devuelve una lista de advertencias.
        No lanza excepciones, solo informa al operador.
        """
        warnings = []

        if cls.SECRET_KEY == "dev-secret-key-change-in-production":
            warnings.append("SECRET_KEY usa el valor por defecto. Cámbiala en producción.")

        if not cls.NVD_API_KEY:
            warnings.append(
                "NVD_API_KEY no configurada. El límite de la API NVD será de 5 req/30s. "
                "Obtén una clave gratuita en https://nvd.nist.gov/developers/request-an-api-key"
            )

        if cls.DEBUG:
            warnings.append("Modo DEBUG activo. No usar en producción.")

        return warnings

    @classmethod
    def summary(cls) -> dict:
        """Devuelve un resumen de la configuración (sin secretos) para logging."""
        return {
            "app_name":        cls.APP_NAME,
            "version":         cls.VERSION,
            "debug":           cls.DEBUG,
            "database":        cls.DATABASE_URL.split("://")[0],
            "nvd_api_key":     "configurada" if cls.NVD_API_KEY else "no configurada",
            "scanner_threads": cls.SCANNER_MAX_THREADS,
            "scanner_timeout": cls.SCANNER_TIMEOUT,
            "port_range":      cls.DEFAULT_PORT_RANGE,
        }
