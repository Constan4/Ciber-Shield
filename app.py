"""
app.py — Punto de entrada de Ciber-Shield (CLI + Flask).
Compatible con Python 3.10+
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
    from api.routes_scan   import bp as scan_bp
    from api.routes_host   import bp as host_bp
    from api.routes_report import bp as report_bp
    app.register_blueprint(scan_bp,   url_prefix="/api")
    app.register_blueprint(host_bp,   url_prefix="/api")
    app.register_blueprint(report_bp, url_prefix="/api")
    logger.info("API blueprints registrados: /api/scans, /api/hosts, /api/reports")
    try:
        from web.views import bp as web_bp
        app.register_blueprint(web_bp)
    except ImportError:
        pass


@click.group()
def cli():
    """Shield de Ciber-Shield — Plataforma de Auditoria de Seguridad"""
    pass


# ── init-db ──────────────────────────────────────────────────

@cli.command("init-db")
@click.option("--reset", is_flag=True)
def cmd_init_db(reset):
    """Inicializa la base de datos."""
    from core.database import reset_db
    click.echo("\n  Ciber-Shield — Init BD\n")
    Config.ensure_dirs()
    if reset:
        click.confirm("  Borrar todos los datos?", abort=True)
        init_db()
        reset_db()
        click.echo("  OK  BD reiniciada desde cero")
    else:
        init_db()
    click.echo("  OK  " + str(health_check()["tables"]) + " tablas listas\n")


# ── status ───────────────────────────────────────────────────

@cli.command("status")
def cmd_status():
    """Estado del sistema."""
    click.echo("\n  Ciber-Shield v" + Config.VERSION + "\n")
    for k, v in Config.summary().items():
        click.echo("  " + k.ljust(22) + str(v))
    click.echo()
    try:
        init_db(echo=False)
        db = health_check()
        color = "green" if db["status"] == "ok" else "red"
        click.echo("  DB: " + click.style(db["status"].upper(), fg=color))
        click.echo("  Tablas: " + str(db["tables"]))
    except Exception as e:
        click.echo(click.style("  Error: " + str(e), fg="red"))
    for w in Config.validate():
        click.echo(click.style("  AVISO  " + w, fg="yellow"))
    click.echo()


# ── scan ─────────────────────────────────────────────────────

@cli.command("scan")
@click.option("--target",    required=True, help="IP, hostname o rango CIDR")
@click.option("--name",      default=None,  help="Nombre de la auditoria")
@click.option("--ports",     default=Config.DEFAULT_PORT_RANGE,
              help="Puertos: 1-1024 | common | all | 22,80,443")
@click.option("--timeout",   default=1.0, type=float)
@click.option("--threads",   default=150, type=int)
@click.option("--no-vuln",   is_flag=True)
@click.option("--no-detect", is_flag=True)
def cmd_scan(target, name, ports, timeout, threads, no_vuln, no_detect):
    """Escaneo completo: discovery, ports, CVEs y deteccion."""
    from datetime import datetime
    from scanner import run_scan, ScanPhase
    from vuln    import run_vuln_analysis
    from detect  import run_detection

    if name is None:
        name = "Auditoria " + target + " - " + datetime.now().strftime("%d/%m/%Y %H:%M")

    vuln_str   = "No" if no_vuln   else "Si (NVD API)"
    detect_str = "No" if no_detect else "Si"

    click.echo("\n  Ciber-Shield\n")
    click.echo("  Objetivo  : " + target)
    click.echo("  Puertos   : " + ports)
    click.echo("  CVEs      : " + vuln_str)
    click.echo("  Deteccion : " + detect_str + "\n")

    init_db(echo=False)

    def _progress(p):
        if p.phase.value in ("done", "failed"):
            return
        filled = int(p.percent / 5)
        bar    = "#" * filled + "." * (20 - filled)
        line   = "\r  [" + bar + "] " + "{:5.1f}".format(p.percent) + "%  "
        line  += p.phase.value.ljust(10) + "  " + p.message[:45].ljust(45)
        click.echo(line, nl=False)

    scan = run_scan(
        name        = name,
        target      = target,
        port_range  = ports,
        timeout     = timeout,
        max_workers = threads,
        progress_cb = _progress,
    )
    click.echo()

    if not scan or scan.status.value == "failed":
        click.echo(click.style("\n  ERROR: El escaneo fallo.", fg="red"))
        return

    if not no_vuln and scan.total_open_ports > 0:
        click.echo("\n  Correlacionando CVEs con NVD API...")
        try:
            run_vuln_analysis(scan.id)
        except Exception as e:
            click.echo(click.style("  AVISO CVE: " + str(e), fg="yellow"))

    if not no_detect and scan.total_open_ports > 0:
        from detect import RULES
        click.echo("  Evaluando " + str(len(RULES)) + " reglas de deteccion...")
        try:
            stats = run_detection(scan.id)
            click.echo("  OK  " + str(stats["findings_total"]) + " hallazgo(s)")
        except Exception as e:
            click.echo(click.style("  AVISO deteccion: " + str(e), fg="yellow"))

    # Recargar scan actualizado
    from core.database import get_db_session
    session = get_db_session()
    scan = session.get(type(scan), scan.id)
    session.close()

    r  = scan.risk_score or 0.0
    rc = "red" if r >= 7 else "yellow" if r >= 4 else "green"
    sev = scan.severity.value.upper() if hasattr(scan, "severity") else ""

    sep = "=" * 52
    click.echo("\n  " + sep)
    click.echo(click.style("  OK  Scan #" + str(scan.id) + " — " + scan.name, fg="green"))
    click.echo("  " + "-" * 52)
    click.echo("  Hosts    : " + str(scan.total_hosts) + "  |  Puertos: " + str(scan.total_open_ports))
    click.echo("  CVEs     : " + str(scan.total_vulns) + "  |  Hallazgos: " + str(scan.total_findings))
    click.echo("  Riesgo   : " + click.style("{:.1f}/10 ({})".format(r, sev), fg=rc, bold=True))
    click.echo("\n  python3 app.py show-scan --id " + str(scan.id) + "\n")


# ── analyze ──────────────────────────────────────────────────

@cli.command("analyze")
@click.option("--id", "scan_id", required=True, type=int)
def cmd_analyze(scan_id):
    """Ejecuta el analisis CVE sobre un scan existente."""
    from vuln import run_vuln_analysis
    init_db(echo=False)
    click.echo("\n  Analizando CVEs del scan #" + str(scan_id) + "...")
    try:
        s = run_vuln_analysis(scan_id)
        click.echo("  OK  Score: {:.1f}/10 | CVEs: {}".format(s.risk_score, s.total_vulns))
        click.echo("      C:" + str(s.vulns_critical) + " H:" + str(s.vulns_high) +
                   " M:" + str(s.vulns_medium) + " L:" + str(s.vulns_low) + "\n")
    except Exception as e:
        click.echo(click.style("  ERROR: " + str(e), fg="red"))


# ── detect ───────────────────────────────────────────────────

@cli.command("detect")
@click.option("--id", "scan_id", required=True, type=int)
def cmd_detect(scan_id):
    """Ejecuta el motor de deteccion de reglas sobre un scan existente."""
    from detect import run_detection, RULES
    init_db(echo=False)
    click.echo("\n  Deteccion en scan #" + str(scan_id) + " (" + str(len(RULES)) + " reglas)...")
    try:
        stats = run_detection(scan_id)
        click.echo("  OK  " + str(stats["findings_total"]) + " hallazgo(s)")
        click.echo("      C:" + str(stats["findings_critical"]) +
                   " H:" + str(stats["findings_high"]) +
                   " M:" + str(stats["findings_medium"]) +
                   " L:" + str(stats["findings_low"]) + "\n")
    except Exception as e:
        click.echo(click.style("  ERROR: " + str(e), fg="red"))


# ── list-scans ───────────────────────────────────────────────

@cli.command("list-scans")
@click.option("--limit", default=10)
def cmd_list_scans(limit):
    """Lista las auditorias guardadas."""
    from core.models import Scan
    from core.database import get_db_session
    init_db(echo=False)
    session = get_db_session()
    try:
        scans = session.query(Scan).order_by(Scan.created_at.desc()).limit(limit).all()
        if not scans:
            click.echo("\n  Sin auditorias. Usa: python3 app.py scan --target IP\n")
            return
        header = "  " + "ID".ljust(5) + " " + "Estado".ljust(12) + " " + \
                 "Objetivo".ljust(22) + " " + "H".ljust(5) + " " + \
                 "P".ljust(6) + " " + "V".ljust(5) + " " + "F".ljust(5) + \
                 " " + "Risk".ljust(7) + " Nombre"
        click.echo("\n" + header)
        click.echo("  " + "-" * 75)
        for s in scans:
            col = {
                "completed": "green", "running": "cyan",
                "failed": "red", "pending": "yellow"
            }.get(s.status.value, "white")
            r   = s.risk_score or 0.0
            rc  = "red" if r >= 7 else "yellow" if r >= 4 else "green"
            row = "  " + str(s.id).ljust(5) + " "
            row += click.style(s.status.value.ljust(12), fg=col) + " "
            row += s.target.ljust(22) + " "
            row += str(s.total_hosts).ljust(5) + " "
            row += str(s.total_open_ports).ljust(6) + " "
            row += str(s.total_vulns).ljust(5) + " "
            row += str(s.total_findings).ljust(5) + " "
            row += click.style("{:.1f}   ".format(r), fg=rc)
            row += " " + s.name[:35]
            click.echo(row)
        click.echo()
    finally:
        session.close()


# ── show-scan ────────────────────────────────────────────────

@cli.command("show-scan")
@click.option("--id", "scan_id", required=True, type=int)
def cmd_show_scan(scan_id):
    """Detalle completo de una auditoria."""
    from core.models import Scan, Host, Port, Vulnerability, Finding
    from core.database import get_db_session
    init_db(echo=False)
    session = get_db_session()
    try:
        scan = session.get(Scan, scan_id)
        if not scan:
            click.echo(click.style("\n  ERROR: Scan #" + str(scan_id) + " no encontrado.\n", fg="red"))
            return

        r   = scan.risk_score or 0.0
        rc  = "red" if r >= 7 else "yellow" if r >= 4 else "green"
        sev = scan.severity.value.upper() if hasattr(scan, "severity") else ""

        click.echo("\n  Auditoria #" + str(scan.id) + " — " + scan.name)
        click.echo("  " + "-" * 60)
        click.echo("  Target  : " + scan.target + "  |  Puertos: " + scan.port_range)
        click.echo("  Estado  : " + click.style(scan.status.value.upper(), fg="green"))
        click.echo("  Hosts   : " + str(scan.total_hosts) +
                   "  Puertos: " + str(scan.total_open_ports) +
                   "  CVEs: " + str(scan.total_vulns) +
                   "  Hallazgos: " + str(scan.total_findings))
        click.echo("  Riesgo  : " + click.style("{:.1f}/10  ({})".format(r, sev), fg=rc, bold=True))

        hosts = (session.query(Host)
                 .filter_by(scan_id=scan_id)
                 .order_by(Host.risk_score.desc())
                 .all())

        for host in hosts:
            hr  = host.risk_score or 0.0
            hrc = "red" if hr >= 7 else "yellow" if hr >= 4 else "green"
            line = "\n  +-- " + host.ip
            if host.hostname:
                line += "  (" + host.hostname + ")"
            click.echo(line)
            if host.os:
                click.echo("  |   OS     : " + host.os)
            click.echo("  |   Riesgo : " + click.style("{:.1f}/10".format(hr), fg=hrc))

            ports = (session.query(Port)
                     .filter_by(host_id=host.id, state="open")
                     .order_by(Port.number)
                     .all())

            for p in ports:
                vulns  = session.query(Vulnerability).filter_by(port_id=p.id).all()
                svc    = (p.service_name or "?")
                if p.service_version:
                    svc += " " + p.service_version[:25]
                danger = click.style(" [!]", fg="yellow") if p.is_dangerous else ""
                click.echo("  |   " + str(p.number).rjust(5) + "/" + p.protocol +
                           "  " + svc.ljust(38) + danger)
                for v in sorted(vulns, key=lambda x: x.cvss_score or 0, reverse=True)[:3]:
                    sv  = v.severity.value.upper() if v.severity else "?"
                    col = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"blue","LOW":"green"}.get(sv,"white")
                    click.echo("  |             " +
                               click.style("[" + sv.ljust(8) + "]", fg=col) +
                               " " + v.cve_id +
                               "  CVSS:{:.1f}".format(v.cvss_score or 0))

            findings = session.query(Finding).filter_by(host_id=host.id).all()
            for f in findings:
                sv  = f.severity.value.upper() if f.severity else "?"
                col = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"blue","LOW":"green"}.get(sv,"white")
                click.echo("  |   " + click.style("[" + f.rule_id + "]", fg=col) +
                           " " + f.rule_name)
        click.echo()
    finally:
        session.close()


# ── report ───────────────────────────────────────────────────

@cli.command("report")
@click.option("--id", "scan_id", required=True, type=int)
@click.option("--format", "fmt", default="html",
              type=click.Choice(["html", "pdf", "both"]))
@click.option("--output", default=None)
def cmd_report(scan_id, fmt, output):
    """Genera un informe HTML/PDF de una auditoria completada."""
    from pathlib import Path
    from report import run_report, is_weasyprint_available
    init_db(echo=False)
    click.echo("\n  Generando informe — Scan #" + str(scan_id) + " (" + fmt.upper() + ")")
    if fmt in ("pdf", "both") and not is_weasyprint_available():
        click.echo(click.style("  AVISO: WeasyPrint no instalado. Generando solo HTML.", fg="yellow"))
        click.echo("     Instalar: pip install WeasyPrint")
        fmt = "html"
    try:
        out_path = Path(output) if output else None
        path = run_report(scan_id, fmt=fmt)
        click.echo(click.style("  OK  Informe: " + str(path), fg="green"))
        click.echo("  Abrir: file://" + str(path.resolve()) + "\n")
    except Exception as e:
        click.echo(click.style("  ERROR: " + str(e), fg="red"))


# ── web ──────────────────────────────────────────────────────

@cli.command("web")
@click.option("--host",  default=Config.FLASK_HOST)
@click.option("--port",  default=Config.FLASK_PORT, type=int)
@click.option("--debug", is_flag=True, default=Config.DEBUG)
def cmd_web(host, port, debug):
    """Lanza el dashboard web + API REST."""
    click.echo("\n  Ciber-Shield — http://" + host + ":" + str(port))
    click.echo("  API:  http://" + host + ":" + str(port) + "/api/health\n")
    create_app().run(host=host, port=port, debug=debug, use_reloader=debug)


# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    for w in Config.validate():
        if "--help" not in sys.argv:
            logger.warning(w)
    cli()
