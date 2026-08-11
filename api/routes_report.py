"""
api/routes_report.py — API REST para generación y descarga de informes.

Endpoints:
    POST /api/scans/{id}/report   → Generar informe HTML o PDF
    GET  /api/reports             → Listar informes generados
"""

import threading
from pathlib import Path
from flask import Blueprint, jsonify, send_file

from core.config   import Config
from core.database import get_db_session
from core.logger   import get_logger
from core.models   import Scan, Report, ScanStatus

logger = get_logger(__name__)
bp     = Blueprint("report_api", __name__)


def _ok(data, status=200):  return jsonify({"status":"ok","data":data}), status
def _err(msg, status=400):  return jsonify({"status":"error","message":msg}), status


@bp.route("/scans/<int:scan_id>/report", methods=["POST"])
def generate_report(scan_id: int):
    """
    POST /api/scans/{id}/report

    Body (JSON):
        format: 'html' | 'pdf' | 'both'  (default: 'html')
    """
    from flask import request
    data   = request.get_json(silent=True) or {}
    fmt    = data.get("format", "html").lower()

    session = get_db_session()
    try:
        scan = session.get(Scan, scan_id)
        if not scan:
            return _err("Auditoría no encontrada", 404)
        if scan.status != ScanStatus.COMPLETED:
            return _err("La auditoría debe estar completada", 409)
    finally:
        session.close()

    result = {"scan_id": scan_id, "format": fmt, "files": []}

    def _gen():
        try:
            from report import run_report
            path = run_report(scan_id, fmt=fmt)
            logger.info(f"Informe generado: {path}")
        except Exception as e:
            logger.exception(f"Error generando informe: {e}")

    thread = threading.Thread(target=_gen, daemon=True)
    thread.start()

    return _ok({**result, "message": "Generación de informe iniciada"}, 202)


@bp.route("/reports", methods=["GET"])
def list_reports():
    """GET /api/reports — Listar informes generados en disco."""
    reports_dir = Config.REPORTS_DIR
    if not reports_dir.exists():
        return _ok({"reports": [], "total": 0})

    files = []
    for f in sorted(reports_dir.glob("report_*.html"), reverse=True):
        stat = f.stat()
        files.append({
            "filename":   f.name,
            "size_bytes": stat.st_size,
            "created":    stat.st_ctime,
        })

    return _ok({"reports": files[:50], "total": len(files)})


@bp.route("/reports/download/<path:filename>", methods=["GET"])
def download_report(filename: str):
    """GET /api/reports/download/{filename} — Descargar un informe."""
    path = Config.REPORTS_DIR / filename
    if not path.exists() or ".." in filename:
        return _err("Informe no encontrado", 404)

    mime = "application/pdf" if filename.endswith(".pdf") else "text/html"
    return send_file(str(path), mimetype=mime, as_attachment=True, download_name=filename)
