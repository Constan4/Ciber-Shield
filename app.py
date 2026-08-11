"""
app.py — Punto de entrada principal de Ciber-Shield.

Proporciona:
    CLI (Click):
        python3 app.py init-db         → Inicializar la base de datos
        python3 app.py web             → Lanzar el dashboard web
        python3 app.py status          → Estado del sistema

    Factory function:
        create_app()                   → Crea la aplicación Flask

Uso rápido:
    python3 app.py init-db
    python3 app.py web
"""

import sys
from pathlib import Path

import click

from core import Config, init_db, health_check, get_logger

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════
# FLASK APP FACTORY
# ══════════════════════════════════════════════════════════════

def create_app() -> "Flask":  # noqa: F821
    """
    Crea y configura la aplicación Flask.

    Registra blueprints de la API REST y del dashboard web,
    configura la BD y los teardown handlers.
    """
    from flask import Flask
    from core.database import close_db_session

    app = Flask(
        __name__,
        template_folder="web/templates",
        static_folder="web/static",
    )
    app.config["SECRET_KEY"]    = Config.SECRET_KEY
    app.config["DEBUG"]         = Config.DEBUG
    app.config["SQLALCHEMY_DATABASE_URI"] = Config.DATABASE_URL

    # Inicializar la base de datos
    init_db()

    # Registrar teardown para cerrar sesiones de BD tras cada request
    app.teardown_appcontext(close_db_session)

    # Registrar blueprints (se añadirán en sprints posteriores)
    _register_blueprints(app)

    logger.info(f"{Config.APP_NAME} v{Config.VERSION} — aplicación Flask creada")
    return app


def _register_blueprints(app: "Flask") -> None:  # noqa: F821
    """Registra los blueprints disponibles."""
    try:
        from api.routes_scan   import bp as scan_bp
        app.register_blueprint(scan_bp, url_prefix="/api")
        logger.debug("Blueprint api/scans registrado")
    except ImportError:
        logger.debug("api/routes_scan aún no implementado — sprint pendiente")

    try:
        from web.views import bp as web_bp
        app.register_blueprint(web_bp)
        logger.debug("Blueprint web/views registrado")
    except ImportError:
        logger.debug("web/views aún no implementado — sprint pendiente")


# ══════════════════════════════════════════════════════════════
# CLI — COMANDOS CLICK
# ══════════════════════════════════════════════════════════════

@click.group()
def cli():
    """
    🛡️  Ciber-Shield — Plataforma de Auditoría de Seguridad

    Usa 'python3 app.py COMANDO --help' para más información
    sobre cada comando.
    """
    pass


@cli.command("init-db")
@click.option("--reset", is_flag=True, default=False,
              help="Eliminar y recrear todas las tablas (BORRA LOS DATOS)")
def cmd_init_db(reset: bool):
    """Inicializa la base de datos y crea las tablas."""
    from core.database import reset_db

    click.echo(f"\n  🛡️  {Config.APP_NAME} — Inicialización de BD\n")

    Config.ensure_dirs()

    if reset:
        click.confirm(
            "  ⚠️  Esto BORRARÁ todos los datos. ¿Continuar?",
            abort=True
        )
        init_db()
        reset_db()
        click.echo("  ✓  Base de datos reiniciada desde cero")
    else:
        init_db()
        click.echo("  ✓  Base de datos inicializada")

    status = health_check()
    click.echo(f"  ✓  Tablas creadas: {status['tables']}")
    click.echo(f"  ✓  Ubicación: {Config.DATABASE_URL}\n")


@cli.command("status")
def cmd_status():
    """Muestra el estado actual del sistema."""
    click.echo(f"\n  🛡️  {Config.APP_NAME} v{Config.VERSION}\n")

    # Config
    summary = Config.summary()
    click.echo("  ── Configuración ────────────────────────")
    for key, val in summary.items():
        click.echo(f"  {key:<20} {val}")

    # Base de datos
    click.echo("\n  ── Base de datos ────────────────────────")
    try:
        init_db(echo=False)
        db_status = health_check()
        status_color = "green" if db_status["status"] == "ok" else "red"
        click.echo(
            f"  Estado:              "
            + click.style(db_status["status"].upper(), fg=status_color)
        )
        click.echo(f"  Tablas:              {db_status['tables']}")
    except Exception as e:
        click.echo(click.style(f"  Error: {e}", fg="red"))

    # Advertencias de configuración
    warnings = Config.validate()
    if warnings:
        click.echo("\n  ── Advertencias ─────────────────────────")
        for w in warnings:
            click.echo(click.style(f"  ⚠  {w}", fg="yellow"))

    click.echo()


@cli.command("web")
@click.option("--host", default=Config.FLASK_HOST, help="Host de escucha")
@click.option("--port", default=Config.FLASK_PORT, type=int, help="Puerto")
@click.option("--debug", is_flag=True, default=Config.DEBUG, help="Modo debug")
def cmd_web(host: str, port: int, debug: bool):
    """Lanza el dashboard web de Ciber-Shield."""
    click.echo(f"\n  🛡️  {Config.APP_NAME} — Dashboard Web")
    click.echo(f"  Abriendo en: http://{host}:{port}\n")

    app = create_app()
    app.run(host=host, port=port, debug=debug, use_reloader=debug)


@cli.command("scan")
@click.option("--target",     required=True, help="IP, hostname o rango CIDR")
@click.option("--name",       default=None,  help="Nombre de la auditoría")
@click.option("--ports",      default=Config.DEFAULT_PORT_RANGE,
              help="Rango de puertos (ej: 1-1024, all, 22,80,443)")
@click.option("--no-vuln",    is_flag=True,  help="Omitir correlación de CVEs")
@click.option("--report",     type=click.Choice(["html", "pdf", "none"]),
              default="html", help="Formato del informe a generar")
def cmd_scan(target: str, name: str, ports: str, no_vuln: bool, report: str):
    """Lanza un escaneo de seguridad completo sobre el objetivo."""
    from datetime import datetime

    _name = name or f"Auditoría {target} — {datetime.now().strftime('%d/%m/%Y %H:%M')}"

    click.echo(f"\n  🛡️  {Config.APP_NAME} — Iniciando auditoría")
    click.echo(f"  Objetivo   : {target}")
    click.echo(f"  Nombre     : {_name}")
    click.echo(f"  Puertos    : {ports}")
    click.echo(f"  CVEs       : {'No' if no_vuln else 'Sí'}")
    click.echo(f"  Informe    : {report}\n")

    # La implementación del scanner se añade en el Sprint 2
    click.echo(
        click.style(
            "  ℹ  El módulo de escaneo se implementará en el Sprint 2.",
            fg="cyan"
        )
    )
    click.echo(
        "     Mientras tanto, puedes inicializar la BD con: "
        "python3 app.py init-db\n"
    )


@cli.command("list-scans")
@click.option("--limit", default=10, help="Número de auditorías a mostrar")
def cmd_list_scans(limit: int):
    """Lista las auditorías guardadas en la base de datos."""
    from core.models import Scan
    from core.database import get_db_session

    init_db(echo=False)
    session = get_db_session()

    try:
        scans = session.query(Scan).order_by(Scan.created_at.desc()).limit(limit).all()

        if not scans:
            click.echo("\n  No hay auditorías guardadas aún.\n")
            return

        click.echo(f"\n  {'ID':<5} {'Estado':<12} {'Objetivo':<25} {'Hosts':<8} {'Riesgo':<8} Nombre")
        click.echo(f"  {'──':<5} {'──────':<12} {'───────':<25} {'─────':<8} {'──────':<8} ─────")

        for scan in scans:
            status_color = {
                "completed": "green", "running": "cyan",
                "failed": "red", "pending": "yellow"
            }.get(scan.status.value, "white")

            click.echo(
                f"  {scan.id:<5} "
                + click.style(f"{scan.status.value:<12}", fg=status_color)
                + f" {scan.target:<25} {scan.total_hosts:<8} "
                + click.style(f"{scan.risk_score:.1f}{'':>5}", fg="red" if scan.risk_score >= 7 else "white")
                + f" {scan.name}"
            )

        click.echo()

    finally:
        session.close()


# ══════════════════════════════════════════════════════════════
# PUNTO DE ENTRADA
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Mostrar advertencias de configuración al arrancar
    warnings = Config.validate()
    if warnings and "--help" not in sys.argv:
        for w in warnings:
            logger.warning(w)

    cli()
