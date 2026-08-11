"""
api/routes_scan.py — REST API de auditorías (Scans) para Ciber-Shield.

Endpoints disponibles:

    GET    /api/scans              → Listar auditorías (paginado)
    POST   /api/scans              → Crear y lanzar nueva auditoría
    GET    /api/scans/{id}         → Detalle de una auditoría
    DELETE /api/scans/{id}         → Eliminar una auditoría
    GET    /api/scans/{id}/hosts   → Hosts descubiertos en la auditoría
    GET    /api/scans/{id}/summary → Resumen de riesgo
    POST   /api/scans/{id}/analyze → Ejecutar análisis CVE + detección
    GET    /api/health             → Estado de la API
"""

import threading
from datetime import datetime, timezone
from typing import Any, Tuple

from flask import Blueprint, jsonify, request

from core.database import get_db_session
from core.logger   import get_logger
from core.models   import Finding, Host, Port, Scan, ScanStatus, Vulnerability

logger = get_logger(__name__)

bp = Blueprint("scan_api", __name__)


# ══════════════════════════════════════════════════════════════
# HELPERS DE RESPUESTA
# ══════════════════════════════════════════════════════════════

def _ok(data: Any, status: int = 200) -> Tuple:
    return jsonify({"status": "ok", "data": data}), status

def _err(message: str, status: int = 400) -> Tuple:
    return jsonify({"status": "error", "message": message}), status

def _not_found(resource: str = "Recurso") -> Tuple:
    return _err(f"{resource} no encontrado", 404)

def _validate_required(data: dict, fields: list) -> list:
    """Devuelve lista de campos requeridos que faltan."""
    return [f for f in fields if not data.get(f)]


# ══════════════════════════════════════════════════════════════
# HEALTH CHECK
# ══════════════════════════════════════════════════════════════

@bp.route("/health", methods=["GET"])
def health():
    """
    GET /api/health

    Comprueba que la API y la BD están operativas.
    """
    from core.database import health_check
    from core.config   import Config

    db_status = health_check()
    return _ok({
        "app":      Config.APP_NAME,
        "version":  Config.VERSION,
        "database": db_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ══════════════════════════════════════════════════════════════
# SCANS — CRUD
# ══════════════════════════════════════════════════════════════

@bp.route("/scans", methods=["GET"])
def list_scans():
    """
    GET /api/scans?page=1&per_page=20&status=completed

    Lista todas las auditorías con paginación y filtrado opcional.

    Query params:
        page:     Número de página (default: 1)
        per_page: Resultados por página (default: 20, max: 100)
        status:   Filtrar por estado (pending/running/completed/failed)
    """
    page     = max(1, request.args.get("page", 1, type=int))
    per_page = min(100, max(1, request.args.get("per_page", 20, type=int)))
    status   = request.args.get("status", "").lower()

    session = get_db_session()
    try:
        query = session.query(Scan).order_by(Scan.created_at.desc())

        if status and status in [s.value for s in ScanStatus]:
            query = query.filter(Scan.status == ScanStatus(status))

        total = query.count()
        scans = query.offset((page - 1) * per_page).limit(per_page).all()

        return _ok({
            "scans":    [s.to_dict() for s in scans],
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "pages":    (total + per_page - 1) // per_page,
        })
    except Exception as e:
        logger.exception("Error listando scans")
        return _err(str(e), 500)
    finally:
        session.close()


@bp.route("/scans", methods=["POST"])
def create_scan():
    """
    POST /api/scans

    Crea y lanza una nueva auditoría en segundo plano.

    Body (JSON):
        name*:        Nombre descriptivo de la auditoría
        target*:      IP, hostname o rango CIDR
        port_range:   Puertos a escanear (default: "1-1024")
        timeout:      Timeout por host/puerto (default: 1.0)
        max_workers:  Hilos concurrentes (default: 150)
        notes:        Notas opcionales
        run_vuln:     Ejecutar análisis CVE tras el scan (default: true)
        run_detect:   Ejecutar motor de detección (default: true)

    Returns:
        201 con el objeto Scan creado (status=pending).
        El escaneo se ejecuta en segundo plano.
        Usar GET /api/scans/{id} para monitorizar el progreso.
    """
    data = request.get_json(silent=True) or {}

    missing = _validate_required(data, ["name", "target"])
    if missing:
        return _err(f"Campos requeridos: {', '.join(missing)}", 422)

    name        = str(data["name"]).strip()[:200]
    target      = str(data["target"]).strip()[:255]
    port_range  = str(data.get("port_range", "1-1024"))
    timeout     = float(data.get("timeout", 1.0))
    max_workers = int(data.get("max_workers", 150))
    notes       = str(data.get("notes", ""))[:500]
    run_vuln    = bool(data.get("run_vuln", True))
    run_detect  = bool(data.get("run_detect", True))

    # Validaciones básicas
    if not name:
        return _err("El campo 'name' no puede estar vacío", 422)
    if not target:
        return _err("El campo 'target' no puede estar vacío", 422)
    if not (0.1 <= timeout <= 30.0):
        return _err("timeout debe estar entre 0.1 y 30.0", 422)
    if not (1 <= max_workers <= 500):
        return _err("max_workers debe estar entre 1 y 500", 422)

    # Crear el registro del scan
    try:
        from scanner.orchestrator import create_scan as _create_scan
        scan_id = _create_scan(name, target, port_range, notes)
    except Exception as e:
        logger.exception("Error creando scan")
        return _err(str(e), 500)

    # Lanzar el pipeline en segundo plano
    def _run_pipeline():
        try:
            from scanner.orchestrator import ScanOrchestrator
            from vuln.risk_scorer      import run_vuln_analysis
            from detect.engine         import run_detection

            orchestrator = ScanOrchestrator(
                scan_id     = scan_id,
                port_range  = port_range,
                timeout     = timeout,
                max_workers = max_workers,
            )
            orchestrator.run()

            if run_vuln:
                run_vuln_analysis(scan_id)

            if run_detect:
                run_detection(scan_id)

        except Exception as exc:
            logger.exception(f"Error en pipeline del scan #{scan_id}: {exc}")

    thread = threading.Thread(target=_run_pipeline, daemon=True, name=f"scan-{scan_id}")
    thread.start()

    logger.info(f"Scan #{scan_id} lanzado en background — target: {target}")

    session = get_db_session()
    try:
        scan = session.get(Scan, scan_id)
        return _ok(scan.to_dict()), 201
    finally:
        session.close()


@bp.route("/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id: int):
    """
    GET /api/scans/{id}

    Devuelve el detalle completo de una auditoría.
    """
    session = get_db_session()
    try:
        scan = session.get(Scan, scan_id)
        if not scan:
            return _not_found("Auditoría")
        return _ok(scan.to_dict())
    finally:
        session.close()


@bp.route("/scans/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id: int):
    """
    DELETE /api/scans/{id}

    Elimina una auditoría y todos sus datos asociados.
    No se puede eliminar una auditoría en estado 'running'.
    """
    session = get_db_session()
    try:
        scan = session.get(Scan, scan_id)
        if not scan:
            return _not_found("Auditoría")
        if scan.status == ScanStatus.RUNNING:
            return _err("No se puede eliminar una auditoría en ejecución", 409)
        session.delete(scan)
        session.commit()
        return _ok({"deleted": scan_id})
    except Exception as e:
        session.rollback()
        logger.exception(f"Error eliminando scan #{scan_id}")
        return _err(str(e), 500)
    finally:
        session.close()


# ══════════════════════════════════════════════════════════════
# HOSTS DE UN SCAN
# ══════════════════════════════════════════════════════════════

@bp.route("/scans/<int:scan_id>/hosts", methods=["GET"])
def list_scan_hosts(scan_id: int):
    """
    GET /api/scans/{id}/hosts?sort=risk&order=desc

    Lista los hosts descubiertos en una auditoría.

    Query params:
        sort:  Campo de ordenación: risk | ip | open_ports (default: risk)
        order: Dirección: asc | desc (default: desc)
    """
    sort  = request.args.get("sort", "risk")
    order = request.args.get("order", "desc").lower()

    session = get_db_session()
    try:
        scan = session.get(Scan, scan_id)
        if not scan:
            return _not_found("Auditoría")

        query = session.query(Host).filter_by(scan_id=scan_id)

        sort_col = {
            "risk":       Host.risk_score,
            "ip":         Host.ip,
            "open_ports": Host.open_ports,
            "vuln_count": Host.vuln_count,
        }.get(sort, Host.risk_score)

        if order == "asc":
            query = query.order_by(sort_col.asc())
        else:
            query = query.order_by(sort_col.desc())

        hosts = query.all()

        return _ok({
            "scan_id": scan_id,
            "hosts":   [h.to_dict() for h in hosts],
            "total":   len(hosts),
        })
    finally:
        session.close()


# ══════════════════════════════════════════════════════════════
# RESUMEN DE RIESGO
# ══════════════════════════════════════════════════════════════

@bp.route("/scans/<int:scan_id>/summary", methods=["GET"])
def scan_summary(scan_id: int):
    """
    GET /api/scans/{id}/summary

    Devuelve un resumen de riesgo completo de la auditoría:
    distribución de severidades, top hosts, top CVEs, hallazgos.
    """
    session = get_db_session()
    try:
        scan = session.get(Scan, scan_id)
        if not scan:
            return _not_found("Auditoría")

        hosts = (
            session.query(Host)
            .filter_by(scan_id=scan_id)
            .order_by(Host.risk_score.desc())
            .all()
        )

        # Top 5 hosts más críticos
        top_hosts = [h.to_dict() for h in hosts[:5]]

        # Top CVEs por CVSS
        top_vulns = []
        for host in hosts[:10]:
            ports = session.query(Port).filter_by(host_id=host.id).all()
            for port in ports:
                vulns = (
                    session.query(Vulnerability)
                    .filter_by(port_id=port.id)
                    .order_by(Vulnerability.cvss_score.desc())
                    .limit(3)
                    .all()
                )
                for v in vulns:
                    top_vulns.append({
                        **v.to_dict(),
                        "host_ip":    host.ip,
                        "port_number": port.number,
                    })

        top_vulns.sort(key=lambda x: x.get("cvss_score") or 0, reverse=True)

        # Hallazgos de detección
        findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        all_findings = []
        for host in hosts:
            findings = session.query(Finding).filter_by(host_id=host.id).all()
            for f in findings:
                sev = f.severity.value if f.severity else "low"
                findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1
                all_findings.append({**f.to_dict(), "host_ip": host.ip})

        # Distribución de severidades de CVEs
        vuln_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for host in hosts:
            ports = session.query(Port).filter_by(host_id=host.id).all()
            for port in ports:
                vulns = session.query(Vulnerability).filter_by(port_id=port.id).all()
                for v in vulns:
                    sev = v.severity.value if v.severity else "low"
                    vuln_by_severity[sev] = vuln_by_severity.get(sev, 0) + 1

        return _ok({
            "scan":               scan.to_dict(),
            "risk_distribution":  {
                "hosts":  {
                    "critical": sum(1 for h in hosts if (h.risk_score or 0) >= 9.0),
                    "high":     sum(1 for h in hosts if 7.0 <= (h.risk_score or 0) < 9.0),
                    "medium":   sum(1 for h in hosts if 4.0 <= (h.risk_score or 0) < 7.0),
                    "low":      sum(1 for h in hosts if 0 < (h.risk_score or 0) < 4.0),
                    "none":     sum(1 for h in hosts if (h.risk_score or 0) == 0),
                },
                "vulnerabilities": vuln_by_severity,
                "findings":        findings_by_severity,
            },
            "top_hosts":          top_hosts,
            "top_vulnerabilities": top_vulns[:10],
            "top_findings":        sorted(
                all_findings,
                key=lambda f: {"critical":4,"high":3,"medium":2,"low":1}.get(
                    f.get("severity","low"), 0
                ),
                reverse=True
            )[:10],
        })
    finally:
        session.close()


# ══════════════════════════════════════════════════════════════
# ANÁLISIS CVE + DETECCIÓN (POST)
# ══════════════════════════════════════════════════════════════

@bp.route("/scans/<int:scan_id>/analyze", methods=["POST"])
def analyze_scan(scan_id: int):
    """
    POST /api/scans/{id}/analyze

    Ejecuta el análisis de vulnerabilidades CVE y el motor de
    detección de reglas sobre un scan ya completado.

    Body (JSON, todos opcionales):
        run_vuln:   Ejecutar correlación CVE (default: true)
        run_detect: Ejecutar motor de detección (default: true)
    """
    session = get_db_session()
    try:
        scan = session.get(Scan, scan_id)
        if not scan:
            return _not_found("Auditoría")
        if scan.status != ScanStatus.COMPLETED:
            return _err(
                f"La auditoría debe estar completada (estado actual: {scan.status.value})",
                409
            )
    finally:
        session.close()

    data       = request.get_json(silent=True) or {}
    run_vuln   = bool(data.get("run_vuln", True))
    run_detect = bool(data.get("run_detect", True))

    def _run():
        try:
            from vuln.risk_scorer import run_vuln_analysis
            from detect.engine    import run_detection
            if run_vuln:
                run_vuln_analysis(scan_id)
            if run_detect:
                run_detection(scan_id)
        except Exception as exc:
            logger.exception(f"Error en análisis del scan #{scan_id}: {exc}")

    thread = threading.Thread(target=_run, daemon=True, name=f"analyze-{scan_id}")
    thread.start()

    return _ok({
        "scan_id":    scan_id,
        "run_vuln":   run_vuln,
        "run_detect": run_detect,
        "message":    "Análisis iniciado en segundo plano",
    }, 202)


# ══════════════════════════════════════════════════════════════
# ERROR HANDLERS DEL BLUEPRINT
# ══════════════════════════════════════════════════════════════

@bp.errorhandler(404)
def not_found_handler(e):
    return _err("Recurso no encontrado", 404)

@bp.errorhandler(405)
def method_not_allowed(e):
    return _err("Método HTTP no permitido en este endpoint", 405)

@bp.errorhandler(500)
def internal_error(e):
    logger.error(f"Error interno en la API: {e}")
    return _err("Error interno del servidor", 500)
