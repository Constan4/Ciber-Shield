"""
app.py — Punto de entrada principal de Ciber-Shield.

Proporciona:
    CLI (Click):
        python3 app.py init-db         → Inicializar la base de datos
        python3 app.py status          → Estado del sistema
        python3 app.py scan            → Lanzar un escaneo
        python3 app.py list-scans      → Listar auditorías guardadas
        python3 app.py show-scan       → Detalle de una auditoría
        python3 app.py web             → Lanzar el dashboard web
"""

import sys
from pathlib import Path

import click

from core import Config, init_db, health_check, get_logger

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════
# FLASK APP FACTORY
# ══════════════════════════════════════════════════════════════

def create_app():
    """Crea y configura la aplicación Flask."""
    from flask import Flask
    from core.database import close_db_session

    app = Flask(
        __name__,
        template_folder="web/templates",
        static_folder="web/static",
    )
    app.config["SECRET_KEY"]    = Config.SECRET_KEY
    app.config["DEBUG"]         = Config.DEBUG

    init_db()
    app.teardown_appcontext(close_db_session)
    _register_blueprints(app)

    logger.info(f"{Config.APP_NAME} v{Config.VERSION} — Flask app creada")
    return app


def _register_blueprints(app) -> None:
    try:
        from api.routes_scan import bp as scan_bp
        app.register_blueprint(scan_bp, url_prefix="/api")
        logger.debug("Blueprint api/scans registrado")
    except ImportError:
        logger.debug("api/routes_scan aún no implementado")

    try:
        from web.views import bp as web_bp
        app.register_blueprint(web_bp)
        logger.debug("Blueprint web/views registrado")
    except ImportError:
        logger.debug("web/views aún no implementado")


# ══════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════

@click.group()
def cli():
    """🛡️  Ciber-Shield — Plataforma de Auditoría de Seguridad"""
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
        click.confirm("  ⚠️  Esto BORRARÁ todos los datos. ¿Continuar?", abort=True)
        init_db()
        reset_db()
        click.echo("  ✓  Base de datos reiniciada")
    else:
        init_db()

    status = health_check()
    click.echo(f"  ✓  Tablas: {status['tables']}")
    click.echo(f"  ✓  BD: {Config.DATABASE_URL}\n")


@cli.command("status")
def cmd_status():
    """Muestra el estado del sistema."""
    click.echo(f"\n  🛡️  {Config.APP_NAME} v{Config.VERSION}\n")

    for key, val in Config.summary().items():
        click.echo(f"  {key:<20} {val}")

    click.echo("\n  ── Base de datos ────────────────────────")
    try:
        init_db(echo=False)
        db = health_check()
        color = "green" if db["status"] == "ok" else "red"
        click.echo("  Estado:              " + click.style(db["status"].upper(), fg=color))
        click.echo(f"  Tablas:              {db['tables']}")
    except Exception as e:
        click.echo(click.style(f"  Error: {e}", fg="red"))

    warnings = Config.validate()
    if warnings:
        click.echo("\n  ── Advertencias ─────────────────────────")
        for w in warnings:
            click.echo(click.style(f"  ⚠  {w}", fg="yellow"))
    click.echo()


@cli.command("scan")
@click.option("--target",   required=True, help="IP, hostname o rango CIDR")
@click.option("--name",     default=None,  help="Nombre de la auditoría")
@click.option("--ports",    default=Config.DEFAULT_PORT_RANGE,
              help="Puertos: 1-1024 | common | all | 22,80,443")
@click.option("--timeout",  default=1.0,   type=float, help="Timeout por host/puerto (seg)")
@click.option("--threads",  default=150,   type=int,   help="Hilos concurrentes")
def cmd_scan(target: str, name: str, ports: str, timeout: float, threads: int):
    """Lanza un escaneo de seguridad completo sobre el objetivo."""
    from datetime import datetime
    from scanner import run_scan, ScanPhase

    _name = name or f"Auditoría {target} — {datetime.now().strftime('%d/%m/%Y %H:%M')}"

    click.echo(f"\n  🛡️  {Config.APP_NAME} — Nuevo escaneo")
    click.echo(f"  Objetivo  : {target}")
    click.echo(f"  Nombre    : {_name}")
    click.echo(f"  Puertos   : {ports}")
    click.echo(f"  Timeout   : {timeout}s | Hilos: {threads}\n")

    init_db(echo=False)

    def _progress(p):
        if p.phase in (ScanPhase.DONE, ScanPhase.FAILED):
            return
        filled = int(p.percent / 5)
        bar    = "█" * filled + "░" * (20 - filled)
        click.echo(
            f"\r  [{bar}] {p.percent:5.1f}%  "
            f"{p.phase.value:<10}  {p.message[:45]:<45}",
            nl=False,
        )

    scan = run_scan(
        name        = _name,
        target      = target,
        port_range  = ports,
        timeout     = timeout,
        max_workers = threads,
        progress_cb = _progress,
    )

    click.echo()  # newline tras la barra

    if not scan or scan.status.value == "failed":
        click.echo(click.style("\n  ✗  El escaneo falló. Consulta los logs.", fg="red"))
        return

    sep = "═" * 52
    click.echo(f"\n  {sep}")
    click.echo(click.style(f"  ✓  Escaneo #{scan.id} completado", fg="green"))
    click.echo(f"  {sep}")
    click.echo(f"  Hosts activos    : {scan.total_hosts}")
    click.echo(f"  Puertos abiertos : {scan.total_open_ports}")
    click.echo(f"  Vulnerabilidades : {scan.total_vulns}")
    r = scan.risk_score or 0.0
    risk_color = "red" if r >= 7 else "yellow" if r >= 4 else "green"
    click.echo("  Risk Score       : " + click.style(f"{r:.1f}/10", fg=risk_color))
    click.echo(f"\n  Ver detalle: python3 app.py show-scan --id {scan.id}\n")


@cli.command("list-scans")
@click.option("--limit", default=10, help="Número de auditorías a mostrar")
def cmd_list_scans(limit: int):
    """Lista las auditorías guardadas."""
    from core.models import Scan
    from core.database import get_db_session

    init_db(echo=False)
    session = get_db_session()

    try:
        scans = session.query(Scan).order_by(Scan.created_at.desc()).limit(limit).all()

        if not scans:
            click.echo("\n  Sin auditorías. Usa: python3 app.py scan --target IP\n")
            return

        click.echo(f"\n  {'ID':<5} {'Estado':<12} {'Objetivo':<22} {'Hosts':<7} {'Ports':<7} {'Riesgo':<8} Nombre")
        click.echo(f"  {'──':<5} {'──────':<12} {'───────':<22} {'─────':<7} {'─────':<7} {'──────':<8} ─────")

        for scan in scans:
            color = {"completed": "green", "running": "cyan",
                     "failed": "red", "pending": "yellow"}.get(scan.status.value, "white")
            r = scan.risk_score or 0.0
            r_color = "red" if r >= 7 else "yellow" if r >= 4 else "green"

            click.echo(
                f"  {scan.id:<5} "
                + click.style(f"{scan.status.value:<12}", fg=color)
                + f" {scan.target:<22} {scan.total_hosts:<7} {scan.total_open_ports:<7} "
                + click.style(f"{r:.1f}{'':>4}", fg=r_color)
                + f"  {scan.name[:40]}"
            )
        click.echo()

    finally:
        session.close()


@cli.command("show-scan")
@click.option("--id", "scan_id", required=True, type=int, help="ID de la auditoría")
def cmd_show_scan(scan_id: int):
    """Muestra el detalle completo de una auditoría."""
    from core.models import Scan, Host, Port
    from core.database import get_db_session

    init_db(echo=False)
    session = get_db_session()

    try:
        scan = session.get(Scan, scan_id)
        if not scan:
            click.echo(click.style(f"\n  ✗  Scan #{scan_id} no encontrado.\n", fg="red"))
            return

        click.echo(f"\n  🛡️  Auditoría #{scan.id} — {scan.name}")
        click.echo(f"  {'─'*55}")
        click.echo(f"  Objetivo : {scan.target}")
        click.echo(f"  Puertos  : {scan.port_range}")
        click.echo(f"  Estado   : " + click.style(scan.status.value, fg="green"))
        click.echo(f"  Hosts    : {scan.total_hosts}")
        click.echo(f"  Puertos  : {scan.total_open_ports}")
        r = scan.risk_score or 0.0
        click.echo("  Riesgo   : " + click.style(f"{r:.1f}/10", fg="red" if r>=7 else "yellow" if r>=4 else "green"))

        hosts = session.query(Host).filter_by(scan_id=scan_id).all()
        for host in hosts:
            click.echo(f"\n  ┌─ {host.ip}")
            if host.hostname:
                click.echo(f"  │  Hostname: {host.hostname}")
            if host.os:
                click.echo(f"  │  OS: {host.os} ({host.os_confidence}%)")
            click.echo(f"  │  Puertos: {host.open_ports}")

            ports = session.query(Port).filter_by(host_id=host.id, state="open").all()
            for p in ports:
                danger = click.style(" ⚠", fg="yellow") if p.is_dangerous else ""
                svc = f"{p.service_name}" + (f" {p.service_version}" if p.service_version else "")
                click.echo(f"  │   {p.number:>5}/{p.protocol}  {svc}{danger}")

        click.echo()

    finally:
        session.close()


@cli.command("web")
@click.option("--host",  default=Config.FLASK_HOST, help="Host de escucha")
@click.option("--port",  default=Config.FLASK_PORT, type=int, help="Puerto")
@click.option("--debug", is_flag=True, default=Config.DEBUG)
def cmd_web(host: str, port: int, debug: bool):
    """Lanza el dashboard web."""
    click.echo(f"\n  🛡️  {Config.APP_NAME} — Dashboard en http://{host}:{port}\n")
    app = create_app()
    app.run(host=host, port=port, debug=debug, use_reloader=debug)


# ══════════════════════════════════════════════════════════════
# PUNTO DE ENTRADA
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    for w in Config.validate():
        if "--help" not in sys.argv:
            logger.warning(w)
    cli()
