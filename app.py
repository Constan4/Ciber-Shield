"""
app.py — Punto de entrada principal de Ciber-Shield.

CLI:
    python3 app.py init-db           → Inicializar BD
    python3 app.py status            → Estado del sistema
    python3 app.py scan              → Escaneo completo (scan + CVEs)
    python3 app.py analyze           → Análisis CVE de un scan existente
    python3 app.py list-scans        → Listar auditorías
    python3 app.py show-scan --id N  → Detalle de una auditoría
    python3 app.py web               → Dashboard web
"""

import sys
from pathlib import Path

import click

from core import Config, init_db, health_check, get_logger

logger = get_logger(__name__)


def create_app():
    from flask import Flask
    from core.database import close_db_session
    app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
    app.config["SECRET_KEY"] = Config.SECRET_KEY
    app.config["DEBUG"]      = Config.DEBUG
    init_db()
    app.teardown_appcontext(close_db_session)
    _register_blueprints(app)
    return app


def _register_blueprints(app) -> None:
    for module, prefix in [("api.routes_scan", "/api"), ("web.views", "")]:
        try:
            import importlib
            mod = importlib.import_module(module)
            app.register_blueprint(mod.bp, url_prefix=prefix)
        except ImportError:
            pass


@click.group()
def cli():
    """🛡️  Ciber-Shield — Plataforma de Auditoría de Seguridad"""
    pass


# ── init-db ──────────────────────────────────────────────────

@cli.command("init-db")
@click.option("--reset", is_flag=True, help="Borrar y recrear todas las tablas")
def cmd_init_db(reset):
    """Inicializa la base de datos."""
    from core.database import reset_db
    click.echo(f"\n  🛡️  {Config.APP_NAME} — Init BD\n")
    Config.ensure_dirs()
    if reset:
        click.confirm("  ⚠️  ¿Borrar todos los datos?", abort=True)
        init_db(); reset_db()
        click.echo("  ✓  BD reiniciada")
    else:
        init_db()
    status = health_check()
    click.echo(f"  ✓  {status['tables']} tablas — {Config.DATABASE_URL}\n")


# ── status ───────────────────────────────────────────────────

@cli.command("status")
def cmd_status():
    """Estado del sistema y configuración."""
    click.echo(f"\n  🛡️  {Config.APP_NAME} v{Config.VERSION}\n")
    for k, v in Config.summary().items():
        click.echo(f"  {k:<22} {v}")
    click.echo("\n  ── Base de datos ────────────────────────")
    try:
        init_db(echo=False)
        db = health_check()
        color = "green" if db["status"] == "ok" else "red"
        click.echo("  Estado:              " + click.style(db["status"].upper(), fg=color))
        click.echo(f"  Tablas:              {db['tables']}")
    except Exception as e:
        click.echo(click.style(f"  Error: {e}", fg="red"))
    for w in Config.validate():
        click.echo(click.style(f"  ⚠  {w}", fg="yellow"))
    click.echo()


# ── scan ─────────────────────────────────────────────────────

@cli.command("scan")
@click.option("--target",   required=True, help="IP, hostname o rango CIDR")
@click.option("--name",     default=None,  help="Nombre de la auditoría")
@click.option("--ports",    default=Config.DEFAULT_PORT_RANGE,
              help="Puertos: 1-1024 | common | all | 22,80,443")
@click.option("--timeout",  default=1.0,   type=float)
@click.option("--threads",  default=150,   type=int)
@click.option("--no-vuln",  is_flag=True,  help="Omitir análisis de CVEs")
def cmd_scan(target, name, ports, timeout, threads, no_vuln):
    """Escaneo completo: discovery → ports → services → CVEs → risk score."""
    from datetime import datetime
    from scanner import run_scan, ScanPhase
    from vuln   import run_vuln_analysis

    _name = name or f"Auditoría {target} — {datetime.now().strftime('%d/%m/%Y %H:%M')}"

    click.echo(f"\n  🛡️  {Config.APP_NAME} — Nuevo escaneo")
    click.echo(f"  Objetivo  : {target}")
    click.echo(f"  Nombre    : {_name}")
    click.echo(f"  Puertos   : {ports}")
    click.echo(f"  CVEs      : {'No' if no_vuln else 'Sí (NVD API)'}\n")

    init_db(echo=False)

    def _progress(p):
        if p.phase in (ScanPhase.DONE, ScanPhase.FAILED):
            return
        filled = int(p.percent / 5)
        bar    = "█" * filled + "░" * (20 - filled)
        click.echo(
            f"\r  [{bar}] {p.percent:5.1f}%  {p.phase.value:<10}  {p.message[:45]:<45}",
            nl=False,
        )

    # ── Fase 1-3: Scanner ─────────────────────────────────────
    scan = run_scan(name=_name, target=target, port_range=ports,
                    timeout=timeout, max_workers=threads, progress_cb=_progress)
    click.echo()

    if not scan or scan.status.value == "failed":
        click.echo(click.style("\n  ✗  El escaneo falló.", fg="red")); return

    # ── Fase 4: CVE Analysis ──────────────────────────────────
    if not no_vuln and scan.total_open_ports > 0:
        click.echo(f"\n  🔍 Correlacionando CVEs con NVD API...")
        try:
            summary = run_vuln_analysis(scan.id)
            # Recargar scan actualizado
            from core.database import get_db_session
            session = get_db_session()
            scan = session.get(type(scan), scan.id)
            session.close()
        except Exception as e:
            click.echo(click.style(f"  ⚠  Análisis CVE falló: {e}", fg="yellow"))
            summary = None
    else:
        summary = None

    # ── Resultado final ───────────────────────────────────────
    click.echo(f"\n  {'═'*52}")
    click.echo(click.style(f"  ✓  Escaneo #{scan.id} completado", fg="green"))
    click.echo(f"  {'═'*52}")
    click.echo(f"  Hosts activos     : {scan.total_hosts}")
    click.echo(f"  Puertos abiertos  : {scan.total_open_ports}")
    click.echo(f"  Vulnerabilidades  : {scan.total_vulns}")
    r = scan.risk_score or 0.0
    r_color = "red" if r >= 7 else "yellow" if r >= 4 else "green"
    click.echo("  Risk Score        : " + click.style(f"{r:.1f}/10", fg=r_color, bold=True))

    if summary:
        click.echo(f"  ├ CRITICAL: {summary.vulns_critical}  HIGH: {summary.vulns_high}  MEDIUM: {summary.vulns_medium}  LOW: {summary.vulns_low}")

    click.echo(f"\n  Ver detalle : python3 app.py show-scan --id {scan.id}")
    click.echo(f"  Dashboard   : python3 app.py web\n")


# ── analyze (CVE en scan ya existente) ───────────────────────

@cli.command("analyze")
@click.option("--id", "scan_id", required=True, type=int, help="ID del scan a analizar")
def cmd_analyze(scan_id):
    """Ejecuta el análisis de CVEs sobre un scan ya escaneado."""
    from vuln import run_vuln_analysis
    init_db(echo=False)
    click.echo(f"\n  🔍 Analizando CVEs del scan #{scan_id}...\n")
    try:
        summary = run_vuln_analysis(scan_id)
        click.echo(f"  ✓  Score:      {summary.risk_score:.1f}/10 ({summary.severity})")
        click.echo(f"  ✓  CVEs:       {summary.total_vulns}")
        click.echo(f"     CRITICAL:{summary.vulns_critical} HIGH:{summary.vulns_high} MEDIUM:{summary.vulns_medium} LOW:{summary.vulns_low}")
    except Exception as e:
        click.echo(click.style(f"  ✗  Error: {e}", fg="red"))
    click.echo()


# ── list-scans ───────────────────────────────────────────────

@cli.command("list-scans")
@click.option("--limit", default=10)
def cmd_list_scans(limit):
    """Lista las auditorías guardadas."""
    from core.models import Scan
    from core.database import get_db_session
    init_db(echo=False)
    session = get_db_session()
    try:
        scans = session.query(Scan).order_by(Scan.created_at.desc()).limit(limit).all()
        if not scans:
            click.echo("\n  Sin auditorías. Usa: python3 app.py scan --target IP\n"); return
        click.echo(f"\n  {'ID':<5} {'Estado':<12} {'Objetivo':<22} {'H':<5} {'P':<6} {'V':<6} {'Risk':<7} Nombre")
        click.echo(f"  {'──':<5} {'──────':<12} {'───────':<22} {'─':<5} {'─':<6} {'─':<6} {'────':<7} ─────")
        for s in scans:
            color = {"completed":"green","running":"cyan","failed":"red","pending":"yellow"}.get(s.status.value,"white")
            r = s.risk_score or 0.0
            rc = "red" if r>=7 else "yellow" if r>=4 else "green"
            click.echo(
                f"  {s.id:<5} " + click.style(f"{s.status.value:<12}", fg=color) +
                f" {s.target:<22} {s.total_hosts:<5} {s.total_open_ports:<6} {s.total_vulns:<6} " +
                click.style(f"{r:.1f}{'':>3}", fg=rc) + f"  {s.name[:38]}"
            )
        click.echo()
    finally:
        session.close()


# ── show-scan ────────────────────────────────────────────────

@cli.command("show-scan")
@click.option("--id", "scan_id", required=True, type=int)
def cmd_show_scan(scan_id):
    """Muestra el detalle completo de una auditoría."""
    from core.models import Scan, Host, Port, Vulnerability
    from core.database import get_db_session
    init_db(echo=False)
    session = get_db_session()
    try:
        scan = session.get(Scan, scan_id)
        if not scan:
            click.echo(click.style(f"\n  ✗  Scan #{scan_id} no encontrado.\n", fg="red")); return

        r = scan.risk_score or 0.0
        rc = "red" if r>=7 else "yellow" if r>=4 else "green"

        click.echo(f"\n  🛡️  Auditoría #{scan.id} — {scan.name}")
        click.echo(f"  {'─'*58}")
        click.echo(f"  Objetivo : {scan.target}  |  Puertos: {scan.port_range}")
        click.echo(f"  Estado   : " + click.style(scan.status.value.upper(), fg="green"))
        click.echo(f"  Hosts    : {scan.total_hosts}  Puertos: {scan.total_open_ports}  CVEs: {scan.total_vulns}")
        click.echo("  Risk     : " + click.style(f"{r:.1f}/10  ({scan.severity.value.upper()})", fg=rc, bold=True))

        hosts = session.query(Host).filter_by(scan_id=scan_id).all()

        for host in hosts:
            hr = host.risk_score or 0.0
            hrc = "red" if hr>=7 else "yellow" if hr>=4 else "green"
            click.echo(f"\n  ┌── {host.ip}")
            if host.hostname: click.echo(f"  │   Hostname : {host.hostname}")
            if host.os:       click.echo(f"  │   OS       : {host.os} ({host.os_confidence}%)")
            click.echo("  │   Riesgo   : " + click.style(f"{hr:.1f}/10", fg=hrc))

            ports = (session.query(Port)
                     .filter_by(host_id=host.id, state="open")
                     .order_by(Port.number).all())

            for p in ports:
                vulns = session.query(Vulnerability).filter_by(port_id=p.id).all()
                svc   = p.service_name or "?"
                if p.service_version: svc += f" {p.service_version[:30]}"
                danger_icon = click.style(" ⚠", fg="yellow") if p.is_dangerous else ""
                click.echo(f"  │   {p.number:>5}/{p.protocol}  {svc:<35}{danger_icon}")

                for v in sorted(vulns, key=lambda x: x.cvss_score or 0, reverse=True)[:3]:
                    sv = v.severity.value.upper() if v.severity else "?"
                    color = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"blue","LOW":"green"}.get(sv,"white")
                    click.echo(
                        f"  │            " +
                        click.style(f"[{sv:<8}]", fg=color) +
                        f" {v.cve_id}  CVSS:{v.cvss_score:.1f}"
                    )
        click.echo()
    finally:
        session.close()


# ── web ──────────────────────────────────────────────────────

@cli.command("web")
@click.option("--host",  default=Config.FLASK_HOST)
@click.option("--port",  default=Config.FLASK_PORT, type=int)
@click.option("--debug", is_flag=True, default=Config.DEBUG)
def cmd_web(host, port, debug):
    """Lanza el dashboard web."""
    click.echo(f"\n  🛡️  {Config.APP_NAME} — http://{host}:{port}\n")
    create_app().run(host=host, port=port, debug=debug, use_reloader=debug)


# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    for w in Config.validate():
        if "--help" not in sys.argv: logger.warning(w)
    cli()
