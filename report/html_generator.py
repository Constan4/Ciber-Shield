"""
report/html_generator.py — Generador de informes de auditoría en HTML.

Produce un informe profesional completo a partir de los datos de un Scan:
    - Portada con clasificación y datos del encargo
    - Resumen ejecutivo con risk score y hallazgos críticos
    - Desglose de vulnerabilidades CVE por severidad
    - Hallazgos del motor de detección con remediaciones
    - Inventario completo de hosts y puertos
    - Recomendaciones priorizadas

El informe es un único archivo HTML auto-contenido (CSS inline) compatible
con WeasyPrint para conversión directa a PDF.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.config   import Config
from core.database import get_session
from core.logger   import get_logger
from core.models   import Finding, Host, Port, Scan, ScanStatus, Severity, Vulnerability

logger = get_logger(__name__)

# Directorio de templates de informes (separado del dashboard web)
_TEMPLATES_DIR = Path(__file__).parent / "templates"


# ══════════════════════════════════════════════════════════════
# RECOLECCIÓN DE DATOS
# ══════════════════════════════════════════════════════════════

def _risk_label(score: float) -> str:
    if score >= 9.0: return "CRÍTICO"
    if score >= 7.0: return "ALTO"
    if score >= 4.0: return "MEDIO"
    if score >  0.0: return "BAJO"
    return "NINGUNO"

def _risk_color(score: float) -> str:
    if score >= 9.0: return "#dc3545"
    if score >= 7.0: return "#fd7e14"
    if score >= 4.0: return "#0dcaf0"
    if score >  0.0: return "#198754"
    return "#6c757d"

def _sev_order(sev: str) -> int:
    return {"critical":4,"high":3,"medium":2,"low":1,"info":0}.get((sev or "").lower(), 0)


def collect_report_data(scan_id: int) -> Optional[dict]:
    """
    Recopila todos los datos necesarios para generar el informe.

    Args:
        scan_id: ID de la auditoría.

    Returns:
        Dict con todos los datos del informe, o None si el scan no existe.
    """
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            logger.error(f"Scan #{scan_id} no encontrado para el informe")
            return None

        # ── Hosts ───────────────────────────────────────────
        hosts = (
            session.query(Host)
            .filter_by(scan_id=scan_id)
            .order_by(Host.risk_score.desc())
            .all()
        )

        hosts_data = []
        all_vulns  = []
        all_findings = []

        vuln_by_sev  = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        find_by_sev  = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for host in hosts:
            ports = (
                session.query(Port)
                .filter_by(host_id=host.id, state="open")
                .order_by(Port.number)
                .all()
            )

            host_vulns    = []
            host_findings = []

            for port in ports:
                vulns = (
                    session.query(Vulnerability)
                    .filter_by(port_id=port.id)
                    .order_by(Vulnerability.cvss_score.desc())
                    .all()
                )
                for v in vulns:
                    sev = (v.severity.value if v.severity else "low").lower()
                    vuln_by_sev[sev] = vuln_by_sev.get(sev, 0) + 1

                    vd = {
                        "cve_id":      v.cve_id,
                        "cvss_score":  v.cvss_score or 0.0,
                        "severity":    sev,
                        "description": (v.description or "")[:200],
                        "vector":      v.vector or "",
                        "host_ip":     host.ip,
                        "port_number": port.number,
                        "service":     port.service_name or "?",
                        "version":     port.service_version or "",
                        "references":  json.loads(v.references or "[]")[:2],
                    }
                    host_vulns.append(vd)
                    all_vulns.append(vd)

            for finding in session.query(Finding).filter_by(host_id=host.id).all():
                sev = (finding.severity.value if finding.severity else "low").lower()
                find_by_sev[sev] = find_by_sev.get(sev, 0) + 1

                fd = {
                    "rule_id":     finding.rule_id,
                    "rule_name":   finding.rule_name,
                    "severity":    sev,
                    "description": finding.description or "",
                    "evidence":    finding.evidence or "",
                    "remediation": finding.remediation or "",
                    "host_ip":     host.ip,
                }
                host_findings.append(fd)
                all_findings.append(fd)

            ports_data = [
                {
                    "number":    p.number,
                    "protocol":  p.protocol,
                    "service":   p.service_name or "desconocido",
                    "version":   p.service_version or "",
                    "banner":    (p.service_banner or "")[:80],
                    "dangerous": p.is_dangerous,
                }
                for p in ports
            ]

            hosts_data.append({
                "ip":            host.ip,
                "hostname":      host.hostname or "",
                "os":            host.os or "Desconocido",
                "os_confidence": host.os_confidence,
                "mac":           host.mac or "",
                "vendor":        host.vendor or "",
                "risk_score":    round(host.risk_score or 0, 1),
                "risk_label":    _risk_label(host.risk_score or 0),
                "risk_color":    _risk_color(host.risk_score or 0),
                "open_ports":    host.open_ports,
                "vuln_count":    host.vuln_count,
                "finding_count": host.finding_count,
                "ports":         ports_data,
                "vulns":         sorted(host_vulns, key=lambda v: v["cvss_score"], reverse=True),
                "findings":      sorted(host_findings, key=lambda f: _sev_order(f["severity"]), reverse=True),
            })

        # Ordenar global
        all_vulns.sort(key=lambda v: v["cvss_score"], reverse=True)
        all_findings.sort(key=lambda f: _sev_order(f["severity"]), reverse=True)

        # ── Recomendaciones ──────────────────────────────────
        recommendations = _build_recommendations(all_findings, all_vulns)

        # ── Duración del scan ─────────────────────────────────
        duration_str = "—"
        if scan.started_at and scan.completed_at:
            secs = (scan.completed_at - scan.started_at).total_seconds()
            if secs < 60:
                duration_str = f"{int(secs)}s"
            else:
                duration_str = f"{int(secs//60)}m {int(secs%60)}s"

        return {
            "generated_at": datetime.now(timezone.utc).strftime("%d de %B de %Y, %H:%M UTC"),
            "scan": {
                "id":           scan.id,
                "name":         scan.name,
                "target":       scan.target,
                "port_range":   scan.port_range,
                "status":       scan.status.value,
                "risk_score":   round(scan.risk_score or 0, 1),
                "risk_label":   _risk_label(scan.risk_score or 0),
                "risk_color":   _risk_color(scan.risk_score or 0),
                "total_hosts":  scan.total_hosts,
                "total_open_ports": scan.total_open_ports,
                "total_vulns":  scan.total_vulns,
                "total_findings": scan.total_findings,
                "created_at":   scan.created_at.strftime("%d/%m/%Y %H:%M") if scan.created_at else "—",
                "started_at":   scan.started_at.strftime("%d/%m/%Y %H:%M") if scan.started_at else "—",
                "completed_at": scan.completed_at.strftime("%d/%m/%Y %H:%M") if scan.completed_at else "—",
                "duration":     duration_str,
                "notes":        scan.notes or "",
            },
            "hosts":       hosts_data,
            "vulns":       all_vulns[:100],   # Top 100 CVEs
            "findings":    all_findings,
            "vuln_by_sev": vuln_by_sev,
            "find_by_sev": find_by_sev,
            "recommendations": recommendations,
            "stats": {
                "risk_gauge_pct": int(min((scan.risk_score or 0) / 10 * 100, 100)),
                "hosts_critical": sum(1 for h in hosts_data if h["risk_score"] >= 9.0),
                "hosts_high":     sum(1 for h in hosts_data if 7.0 <= h["risk_score"] < 9.0),
                "hosts_medium":   sum(1 for h in hosts_data if 4.0 <= h["risk_score"] < 7.0),
                "hosts_low":      sum(1 for h in hosts_data if 0 < h["risk_score"] < 4.0),
                "hosts_none":     sum(1 for h in hosts_data if h["risk_score"] == 0),
            },
        }


def _build_recommendations(findings: List[dict], vulns: List[dict]) -> List[dict]:
    """
    Genera recomendaciones priorizadas combinando hallazgos y CVEs críticos.
    """
    recs = []

    # Recomendaciones de hallazgos (sin duplicados por tipo de regla)
    seen_rules = set()
    for f in findings:
        if f["rule_id"] not in seen_rules and f["remediation"]:
            seen_rules.add(f["rule_id"])
            recs.append({
                "priority":    _sev_order(f["severity"]),
                "severity":    f["severity"],
                "title":       f["rule_name"],
                "description": f["description"][:300],
                "action":      f["remediation"],
                "hosts":       [f["host_ip"]],
                "type":        "detection",
            })

    # Agregar hosts a recomendaciones existentes
    for f in findings:
        for rec in recs:
            if rec["title"] == f["rule_name"] and f["host_ip"] not in rec["hosts"]:
                rec["hosts"].append(f["host_ip"])

    # Recomendaciones de CVEs críticos y altos únicos
    seen_cves = set()
    for v in vulns:
        if v["cvss_score"] >= 7.0 and v["cve_id"] not in seen_cves:
            seen_cves.add(v["cve_id"])
            recs.append({
                "priority":    4 if v["cvss_score"] >= 9 else 3,
                "severity":    "critical" if v["cvss_score"] >= 9 else "high",
                "title":       f"Vulnerabilidad {v['cve_id']} — {v['service']} {v['version']}",
                "description": v["description"],
                "action":      f"Actualizar el servicio {v['service']} a la versión más reciente. "
                               f"Verificar el parche disponible para {v['cve_id']}.",
                "hosts":       [v["host_ip"]],
                "type":        "cve",
            })
            if len(seen_cves) >= 10:
                break

    recs.sort(key=lambda r: r["priority"], reverse=True)
    return recs[:20]


# ══════════════════════════════════════════════════════════════
# RENDERIZADO HTML
# ══════════════════════════════════════════════════════════════

class HTMLReportGenerator:
    """
    Genera informes de auditoría en formato HTML profesional.

    Uso:
        gen   = HTMLReportGenerator(scan_id=1)
        path  = gen.generate()
        print(f"Informe en: {path}")
    """

    def __init__(self, scan_id: int) -> None:
        self.scan_id = scan_id
        self._jinja  = Environment(
            loader        = FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape    = select_autoescape(["html"]),
            trim_blocks   = True,
            lstrip_blocks = True,
        )
        # Filtros personalizados
        self._jinja.filters["risk_color"] = _risk_color
        self._jinja.filters["risk_label"] = _risk_label

    def generate(self, output_path: Optional[Path] = None) -> Path:
        """
        Genera el informe HTML y lo guarda en disco.

        Args:
            output_path: Ruta de destino opcional.
                         Por defecto: reports/report_{scan_id}_{timestamp}.html

        Returns:
            Path del archivo HTML generado.

        Raises:
            ValueError: Si el scan_id no existe.
            RuntimeError: Si hay un error al renderizar el template.
        """
        Config.ensure_dirs()

        logger.info(f"Generando informe HTML para scan #{self.scan_id}")

        data = collect_report_data(self.scan_id)
        if data is None:
            raise ValueError(f"Scan #{self.scan_id} no encontrado")

        try:
            template = self._jinja.get_template("report.html")
            html     = template.render(**data)
        except Exception as exc:
            raise RuntimeError(f"Error al renderizar el template del informe: {exc}") from exc

        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        path  = output_path or (Config.REPORTS_DIR / f"report_{self.scan_id}_{ts}.html")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")

        size_kb = path.stat().st_size // 1024
        logger.info(f"Informe HTML generado: {path} ({size_kb} KB)")

        return path
