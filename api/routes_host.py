"""
api/routes_host.py — REST API de hosts para Ciber-Shield.

Endpoints:

    GET /api/hosts/{id}                  → Detalle de un host
    GET /api/hosts/{id}/ports            → Puertos del host
    GET /api/hosts/{id}/vulnerabilities  → CVEs correlacionados
    GET /api/hosts/{id}/findings         → Hallazgos de detección
    GET /api/hosts/{id}/full             → Todo en una sola respuesta
"""

from flask import Blueprint, jsonify, request

from core.database import get_db_session
from core.logger   import get_logger
from core.models   import Finding, Host, Port, Vulnerability

logger = get_logger(__name__)

bp = Blueprint("host_api", __name__)


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════

def _ok(data, status=200):
    return jsonify({"status": "ok", "data": data}), status

def _err(msg, status=400):
    return jsonify({"status": "error", "message": msg}), status

def _get_host_or_404(session, host_id):
    host = session.get(Host, host_id)
    if not host:
        return None, _err("Host no encontrado", 404)
    return host, None


# ══════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════

@bp.route("/hosts/<int:host_id>", methods=["GET"])
def get_host(host_id: int):
    """
    GET /api/hosts/{id}

    Devuelve la información del host: IP, hostname, OS,
    risk_score, métricas de puertos y vulnerabilidades.
    """
    session = get_db_session()
    try:
        host, err = _get_host_or_404(session, host_id)
        if err:
            return err
        return _ok(host.to_dict())
    finally:
        session.close()


@bp.route("/hosts/<int:host_id>/ports", methods=["GET"])
def get_host_ports(host_id: int):
    """
    GET /api/hosts/{id}/ports?state=open&sort=number

    Lista los puertos del host con su información de servicio.

    Query params:
        state:  Filtrar por estado: open | closed | filtered (default: open)
        sort:   Ordenar por: number | service | risk (default: number)
    """
    state = request.args.get("state", "open")
    sort  = request.args.get("sort", "number")

    session = get_db_session()
    try:
        host, err = _get_host_or_404(session, host_id)
        if err:
            return err

        query = session.query(Port).filter_by(host_id=host_id)
        if state:
            query = query.filter_by(state=state)

        sort_col = {
            "number":  Port.number,
            "service": Port.service_name,
        }.get(sort, Port.number)
        ports = query.order_by(sort_col).all()

        # Para cada puerto, incluir el conteo de vulns
        ports_data = []
        for p in ports:
            d = p.to_dict()
            d["vuln_count"] = session.query(Vulnerability).filter_by(port_id=p.id).count()
            ports_data.append(d)

        return _ok({
            "host_id":   host_id,
            "host_ip":   host.ip,
            "ports":     ports_data,
            "total":     len(ports_data),
        })
    finally:
        session.close()


@bp.route("/hosts/<int:host_id>/vulnerabilities", methods=["GET"])
def get_host_vulnerabilities(host_id: int):
    """
    GET /api/hosts/{id}/vulnerabilities?severity=high&sort=cvss

    Lista todas las vulnerabilidades CVE encontradas en el host.

    Query params:
        severity: Filtrar por severidad mínima: critical|high|medium|low
        sort:     Ordenar por: cvss | cve_id | published (default: cvss)
        limit:    Máximo de resultados (default: 50)
    """
    severity = request.args.get("severity", "").upper()
    sort     = request.args.get("sort", "cvss")
    limit    = min(200, max(1, request.args.get("limit", 50, type=int)))

    session = get_db_session()
    try:
        host, err = _get_host_or_404(session, host_id)
        if err:
            return err

        # Obtener todas las vulns del host (a través de sus puertos)
        ports = session.query(Port).filter_by(host_id=host_id).all()

        all_vulns = []
        for port in ports:
            query = session.query(Vulnerability).filter_by(port_id=port.id)

            vulns = query.all()
            for v in vulns:
                vd = v.to_dict()
                vd["port_number"]   = port.number
                vd["service_name"]  = port.service_name
                all_vulns.append(vd)

        # Filtrar por severidad mínima
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
        if severity and severity in sev_order:
            min_sev = sev_order[severity]
            all_vulns = [
                v for v in all_vulns
                if sev_order.get((v.get("severity") or "").upper(), 0) >= min_sev
            ]

        # Ordenar
        if sort == "cvss":
            all_vulns.sort(key=lambda v: v.get("cvss_score") or 0, reverse=True)
        elif sort == "cve_id":
            all_vulns.sort(key=lambda v: v.get("cve_id") or "")
        elif sort == "published":
            all_vulns.sort(key=lambda v: v.get("published") or "", reverse=True)

        return _ok({
            "host_id":         host_id,
            "host_ip":         host.ip,
            "vulnerabilities": all_vulns[:limit],
            "total":           len(all_vulns),
        })
    finally:
        session.close()


@bp.route("/hosts/<int:host_id>/findings", methods=["GET"])
def get_host_findings(host_id: int):
    """
    GET /api/hosts/{id}/findings?severity=high

    Lista los hallazgos del motor de detección para el host.

    Query params:
        severity: Filtrar por severidad: critical|high|medium|low
    """
    severity = request.args.get("severity", "").lower()

    session = get_db_session()
    try:
        host, err = _get_host_or_404(session, host_id)
        if err:
            return err

        query = session.query(Finding).filter_by(host_id=host_id)

        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if severity and severity in sev_order:
            min_sev = sev_order[severity]
            findings = [
                f for f in query.all()
                if sev_order.get(
                    f.severity.value if f.severity else "low", 0
                ) >= min_sev
            ]
        else:
            findings = query.all()

        # Ordenar por severidad descendente
        findings.sort(
            key=lambda f: sev_order.get(
                f.severity.value if f.severity else "low", 0
            ),
            reverse=True,
        )

        return _ok({
            "host_id":  host_id,
            "host_ip":  host.ip,
            "findings": [f.to_dict() for f in findings],
            "total":    len(findings),
        })
    finally:
        session.close()


@bp.route("/hosts/<int:host_id>/full", methods=["GET"])
def get_host_full(host_id: int):
    """
    GET /api/hosts/{id}/full

    Devuelve toda la información del host en una sola respuesta:
    metadatos + puertos + vulnerabilidades + hallazgos.

    Útil para cargar el detalle completo del host en el dashboard.
    """
    session = get_db_session()
    try:
        host, err = _get_host_or_404(session, host_id)
        if err:
            return err

        # Puertos
        ports = session.query(Port).filter_by(host_id=host_id, state="open").all()

        ports_data = []
        all_vulns  = []

        for p in ports:
            pd = p.to_dict()

            vulns = (
                session.query(Vulnerability)
                .filter_by(port_id=p.id)
                .order_by(Vulnerability.cvss_score.desc())
                .all()
            )
            pd["vulnerabilities"] = [v.to_dict() for v in vulns]
            pd["vuln_count"]      = len(vulns)
            ports_data.append(pd)

            for v in vulns:
                vd = v.to_dict()
                vd.update({"port_number": p.number, "service_name": p.service_name})
                all_vulns.append(vd)

        # Findings
        findings = (
            session.query(Finding)
            .filter_by(host_id=host_id)
            .all()
        )
        findings.sort(
            key=lambda f: {"critical":4,"high":3,"medium":2,"low":1}.get(
                f.severity.value if f.severity else "low", 0
            ),
            reverse=True,
        )

        all_vulns.sort(
            key=lambda v: v.get("cvss_score") or 0, reverse=True
        )

        return _ok({
            "host":            host.to_dict(),
            "ports":           ports_data,
            "vulnerabilities": all_vulns,
            "findings":        [f.to_dict() for f in findings],
            "stats": {
                "open_ports":  len(ports_data),
                "total_vulns": len(all_vulns),
                "total_findings": len(findings),
            },
        })
    finally:
        session.close()


# ══════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ══════════════════════════════════════════════════════════════

@bp.errorhandler(404)
def not_found_handler(e):
    return _err("Host no encontrado", 404)

@bp.errorhandler(500)
def internal_error(e):
    return _err("Error interno del servidor", 500)
