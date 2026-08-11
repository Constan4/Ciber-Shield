"""
app.py — Punto de entrada de Ciber-Shield (CLI + Flask).

CLI:
    python3 app.py init-db           → Inicializar BD
    python3 app.py status            → Estado del sistema
    python3 app.py scan              → Escaneo completo
    python3 app.py analyze --id N    → Analizar CVEs de un scan existente
    python3 app.py detect --id N     → Ejecutar reglas de detección
    python3 app.py list-scans        → Listar auditorías
    python3 app.py show-scan --id N  → Detalle de una auditoría
    python3 app.py web               → Dashboard web + API REST
"""

import sys
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


def _register_blueprints(app):
    from api.routes_scan import bp as scan_bp
    from api.routes_host import bp as host_bp
    app.register_blueprint(scan_bp, url_prefix="/api")
    app.register_blueprint(host_bp, url_prefix="/api")
    logger.info("API blueprints registrados: /api/scans, /api/hosts, /api/health")
    try:
        from web.views import bp as web_bp
        app.register_blueprint(web_bp)
    except ImportError:
        pass


@click.group()
def cli():
    """🛡️  Ciber-Shield — Plataforma de Auditoría de Seguridad"""
    pass


@cli.command("init-db")
@click.option("--reset", is_flag=True)
def cmd_init_db(reset):
    """Inicializa la base de datos."""
    from core.database import reset_db
    click.echo(f"\n  🛡️  {Config.APP_NAME} — Init BD\n")
    Config.ensure_dirs()
    if reset:
        click.confirm("  ⚠️  ¿Borrar todos los datos?", abort=True)
        init_db(); reset_db()
        click.echo("  ✓  BD reiniciada desde cero")
    else:
        init_db()
    click.echo(f"  ✓  {health_check()['tables']} tablas listas\n")


@cli.command("status")
def cmd_status():
    """Estado del sistema."""
    click.echo(f"\n  🛡️  {Config.APP_NAME} v{Config.VERSION}\n")
    for k, v in Config.summary().items():
        click.echo(f"  {k:<22} {v}")
    click.echo()
    try:
        init_db(echo=False)
        db = health_check()
        click.echo("  DB: " + click.style(db["status"].upper(), fg="green"))
        click.echo(f"  Tablas: {db['tables']}")
    except Exception as e:
        click.echo(click.style(f"  DB Error: {e}", fg="red"))
    for w in Config.validate():
        click.echo(click.style(f"  ⚠  {w}", fg="yellow"))
    click.echo()


@cli.command("scan")
@click.option("--target",   required=True)
@click.option("--name",     default=None)
@click.option("--ports",    default=Config.DEFAULT_PORT_RANGE)
@click.option("--timeout",  default=1.0, type=float)
@click.option("--threads",  default=150, type=int)
@click.option("--no-vuln",  is_flag=True)
@click.option("--no-detect",is_flag=True)
def cmd_scan(target, name, ports, timeout, threads, no_vuln, no_detect):
    """Escaneo completo: discovery → ports → CVEs → detección."""
    from datetime import datetime
    from scanner import run_scan, ScanPhase
    from vuln    import run_vuln_analysis
    from detect  import run_detection

    _name = name or f"Auditoría {target} — {datetime.now().strftime('%d/%m/%Y %H:%M')}"

    click.echo(f"\n  🛡️  {Config.APP_NAME}\n")
    click.echo(f"  Objetivo  : {target}")
    click.echo(f"  Puertos   : {ports}")
    click.echo(f"  CVEs      : {'No' if no_vuln else 'Sí'}")
    click.echo(f"  Detección : {'No' if no_detect else 'Sí'}\n")

    init_db(echo=False)

    def _progress(p):
        if p.phase.value in ("done", "failed"): return
        filled = int(p.percent / 5)
        bar = "█" * filled + "░" * (20 - filled)
        click.echo(f"\r  [{bar}] {p.percent:5.1f}%  {p.phase.value:<10}  {p.message[:45]:<45}", nl=False)

    scan = run_scan(name=_name, target=target, port_range=ports,
                    timeout=timeout, max_workers=threads, progress_cb=_progress)
    click.echo()

    if not scan or scan.status.value == "failed":
        click.echo(click.style("\n  ✗  El escaneo falló.", fg="red")); return

    if not no_vuln and scan.total_open_ports > 0:
        click.echo(f"\n  🔍 Correlacionando CVEs...")
        try:
            run_vuln_analysis(scan.id)
        except Exception as e:
            click.echo(click.style(f"  ⚠  CVE analysis: {e}", fg="yellow"))

    if not no_detect and scan.total_open_ports > 0:
        click.echo(f"  🔎 Evaluando reglas de detección ({len(__import__('detect').RULES)} reglas)...")
        try:
            stats = run_detection(scan.id)
            click.echo(f"  ✓  {stats['findings_total']} hallazgo(s)")
        except Exception as e:
            click.echo(click.style(f"  ⚠  Detection: {e}", fg="yellow"))

    # Recargar scan
    from core.database import get_db_session
    session = get_db_session()
    scan = session.get(type(scan), scan.id)
    session.close()

    r = scan.risk_score or 0.0
    rc = "red" if r >= 7 else "yellow" if r >= 4 else "green"
    click.echo(f"\n  {'═'*52}")
    click.echo(click.style(f"  ✓  Scan #{scan.id} — {scan.name}", fg="green"))
    click.echo(f"  {'─'*52}")
    click.echo(f"  Hosts    : {scan.total_hosts}  |  Puertos: {scan.total_open_ports}")
    click.echo(f"  CVEs     : {scan.total_vulns}  |  Hallazgos: {scan.total_findings}")
    click.echo("  Riesgo   : " + click.style(f"{r:.1f}/10 ({scan.severity.value.upper()})", fg=rc, bold=True))
    click.echo(f"\n  python3 app.py show-scan --id {scan.id}\n")


@cli.command("analyze")
@click.option("--id", "scan_id", required=True, type=int)
def cmd_analyze(scan_id):
    """Ejecuta el análisis CVE sobre un scan existente."""
    from vuln import run_vuln_analysis
    init_db(echo=False)
    click.echo(f"\n  🔍 Analizando CVEs del scan #{scan_id}...")
    try:
        s = run_vuln_analysis(scan_id)
        click.echo(f"  ✓  Score: {s.risk_score:.1f}/10 | CVEs: {s.total_vulns}")
        click.echo(f"     C:{s.vulns_critical} H:{s.vulns_high} M:{s.vulns_medium} L:{s.vulns_low}\n")
    except Exception as e:
        click.echo(click.style(f"  ✗  {e}", fg="red"))


@cli.command("detect")
@click.option("--id", "scan_id", required=True, type=int)
def cmd_detect(scan_id):
    """Ejecuta el motor de detección de reglas sobre un scan existente."""
    from detect import run_detection, RULES
    init_db(echo=False)
    click.echo(f"\n  🔎 Detección en scan #{scan_id} ({len(RULES)} reglas)...")
    try:
        stats = run_detection(scan_id)
        click.echo(f"  ✓  {stats['findings_total']} hallazgo(s)")
        click.echo(f"     C:{stats['findings_critical']} H:{stats['findings_high']} M:{stats['findings_medium']} L:{stats['findings_low']}\n")
    except Exception as e:
        click.echo(click.style(f"  ✗  {e}", fg="red"))


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
        click.echo(f"\n  {'ID':<5} {'Estado':<12} {'Objetivo':<22} {'H':<5} {'P':<6} {'V':<5} {'F':<5} {'Risk':<7} Nombre")
        click.echo(f"  {'──':<5} {'──────':<12} {'───────':<22} {'─':<5} {'─':<6} {'─':<5} {'─':<5} {'────':<7} ─────")
        for s in scans:
            col = {"completed":"green","running":"cyan","failed":"red","pending":"yellow"}.get(s.status.value,"white")
            r   = s.risk_score or 0.0
            rc  = "red" if r>=7 else "yellow" if r>=4 else "green"
            click.echo(
                f"  {s.id:<5} " + click.style(f"{s.status.value:<12}", fg=col) +
                f" {s.target:<22} {s.total_hosts:<5} {s.total_open_ports:<6} {s.total_vulns:<5} {s.total_findings:<5} " +
                click.style(f"{r:.1f}{'':>3}", fg=rc) + f"  {s.name[:35]}"
            )
        click.echo()
    finally:
        session.close()


@cli.command("show-scan")
@click.option("--id", "scan_id", required=True, type=int)
def cmd_show_scan(scan_id):
    """Detalle completo de una auditoría."""
    from core.models import Scan, Host, Port, Vulnerability, Finding
    from core.database import get_db_session
    init_db(echo=False)
    session = get_db_session()
    try:
        scan = session.get(Scan, scan_id)
        if not scan:
            click.echo(click.style(f"\n  ✗  Scan #{scan_id} no encontrado.\n", fg="red")); return

        r  = scan.risk_score or 0.0
        rc = "red" if r>=7 else "yellow" if r>=4 else "green"

        click.echo(f"\n  🛡️  #{scan.id} — {scan.name}")
        click.echo(f"  {'─'*60}")
        click.echo(f"  Target  : {scan.target}  |  Puertos: {scan.port_range}")
        click.echo(f"  Estado  : " + click.style(scan.status.value.upper(), fg="green"))
        click.echo(f"  Hosts   : {scan.total_hosts}  Puertos: {scan.total_open_ports}  CVEs: {scan.total_vulns}  Hallazgos: {scan.total_findings}")
        click.echo("  Riesgo  : " + click.style(f"{r:.1f}/10  ({scan.severity.value.upper()})", fg=rc, bold=True))

        hosts = session.query(Host).filter_by(scan_id=scan_id).order_by(Host.risk_score.desc()).all()
        for host in hosts:
            hr  = host.risk_score or 0.0
            hrc = "red" if hr>=7 else "yellow" if hr>=4 else "green"
            click.echo(f"\n  ┌── {host.ip}" + (f"  ({host.hostname})" if host.hostname else ""))
            if host.os: click.echo(f"  │   OS     : {host.os}")
            click.echo("  │   Riesgo : " + click.style(f"{hr:.1f}/10", fg=hrc))

            ports = session.query(Port).filter_by(host_id=host.id, state="open").order_by(Port.number).all()
            for p in ports:
                vulns  = session.query(Vulnerability).filter_by(port_id=p.id).all()
                svc    = (p.service_name or "?") + (f" {p.service_version[:25]}" if p.service_version else "")
                danger = click.style(" ⚠", fg="yellow") if p.is_dangerous else ""
                click.echo(f"  │   {p.number:>5}/{p.protocol}  {svc:<38}{danger}")
                for v in sorted(vulns, key=lambda x: x.cvss_score or 0, reverse=True)[:3]:
                    sv  = v.severity.value.upper() if v.severity else "?"
                    col = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"blue","LOW":"green"}.get(sv,"white")
                    click.echo("  │             " + click.style(f"[{sv:<8}]", fg=col) + f" {v.cve_id}  CVSS:{v.cvss_score:.1f}")

            findings = session.query(Finding).filter_by(host_id=host.id).all()
            for f in findings:
                sv  = f.severity.value.upper() if f.severity else "?"
                col = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"blue","LOW":"green"}.get(sv,"white")
                click.echo("  │   " + click.style(f"[{f.rule_id}]", fg=col) + f" {f.rule_name}")
        click.echo()
    finally:
        session.close()


@cli.command("web")
@click.option("--host",  default=Config.FLASK_HOST)
@click.option("--port",  default=Config.FLASK_PORT, type=int)
@click.option("--debug", is_flag=True, default=Config.DEBUG)
def cmd_web(host, port, debug):
    """Lanza el dashboard web + API REST."""
    click.echo(f"\n  🛡️  {Config.APP_NAME} — http://{host}:{port}")
    click.echo(f"  API:  http://{host}:{port}/api/health\n")
    create_app().run(host=host, port=port, debug=debug, use_reloader=debug)


if __name__ == "__main__":
    for w in Config.validate():
        if "--help" not in sys.argv: logger.warning(w)
    cli()
