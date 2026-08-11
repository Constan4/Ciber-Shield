"""
web/views.py — Rutas del dashboard web de Ciber-Shield.
"""

import json
from flask import Blueprint, redirect, render_template, url_for

from core.database import get_db_session
from core.logger   import get_logger
from core.models   import Finding, Host, Port, Scan, ScanStatus, Vulnerability

logger = get_logger(__name__)

bp = Blueprint("web", __name__, template_folder="templates",
               static_folder="static", static_url_path="/static")


def _risk_label(s): return ("CRITICAL" if s>=9 else "HIGH" if s>=7 else "MEDIUM" if s>=4 else "LOW" if s>0 else "NONE")
def _risk_color(s): return ("danger"   if s>=9 else "warning" if s>=7 else "info"   if s>=4 else "success" if s>0 else "secondary")
def _sev_order(sv): return {"critical":4,"high":3,"medium":2,"low":1}.get((sv or "").lower(), 0)


@bp.route("/")
def index():
    session = get_db_session()
    try:
        scans = session.query(Scan).order_by(Scan.created_at.desc()).all()
        for s in scans:
            s._risk_label = _risk_label(s.risk_score or 0)
            s._risk_color = _risk_color(s.risk_score or 0)

        vuln_counts = {"critical":0,"high":0,"medium":0,"low":0}
        for v in session.query(Vulnerability).all():
            sev = (v.severity.value if v.severity else "low").lower()
            if sev in vuln_counts: vuln_counts[sev] += 1

        completed = [s for s in scans if s.status == ScanStatus.COMPLETED][:8]

        return render_template("index.html",
            scans=scans,
            total_scans=len(scans),
            total_hosts=session.query(Host).count(),
            total_open_ports=session.query(Port).filter_by(state="open").count(),
            total_vulns=sum(vuln_counts.values()),
            active_scans=sum(1 for s in scans if s.status == ScanStatus.RUNNING),
            chart_severity=json.dumps({"labels":["Critical","High","Medium","Low"],
                "data":[vuln_counts["critical"],vuln_counts["high"],vuln_counts["medium"],vuln_counts["low"]]}),
            chart_risk=json.dumps({"labels":[s.name[:20] for s in completed],
                "data":[round(s.risk_score or 0,1) for s in completed]}),
        )
    finally:
        session.close()


@bp.route("/scans/<int:scan_id>")
def scan_detail(scan_id):
    session = get_db_session()
    try:
        scan = session.get(Scan, scan_id)
        if not scan: return redirect(url_for("web.index"))

        hosts = session.query(Host).filter_by(scan_id=scan_id).order_by(Host.risk_score.desc()).all()
        for h in hosts:
            h._risk_label = _risk_label(h.risk_score or 0)
            h._risk_color = _risk_color(h.risk_score or 0)

        risk_dist = {
            "critical": sum(1 for h in hosts if (h.risk_score or 0)>=9),
            "high":     sum(1 for h in hosts if 7<=(h.risk_score or 0)<9),
            "medium":   sum(1 for h in hosts if 4<=(h.risk_score or 0)<7),
            "low":      sum(1 for h in hosts if 0<(h.risk_score or 0)<4),
            "none":     sum(1 for h in hosts if (h.risk_score or 0)==0),
        }

        vuln_dist = {"critical":0,"high":0,"medium":0,"low":0}
        all_vulns = []
        all_findings = []

        for host in hosts:
            ports = session.query(Port).filter_by(host_id=host.id).all()
            for port in ports:
                vulns = session.query(Vulnerability).filter_by(port_id=port.id).order_by(Vulnerability.cvss_score.desc()).all()
                for v in vulns:
                    sev = (v.severity.value if v.severity else "low").lower()
                    if sev in vuln_dist: vuln_dist[sev]+=1
                    vd = v.to_dict()
                    vd.update({"host_ip":host.ip,"host_id":host.id,"port_number":port.number,"service":port.service_name or "?"})
                    vd["_color"] = {"critical":"danger","high":"warning","medium":"info","low":"success"}.get(sev,"secondary")
                    all_vulns.append(vd)

            for f in session.query(Finding).filter_by(host_id=host.id).all():
                fd = f.to_dict()
                fd.update({"host_ip":host.ip,"host_id":host.id})
                fd["_color"] = {"critical":"danger","high":"warning","medium":"info","low":"success"}.get(fd.get("severity",""),"secondary")
                all_findings.append(fd)

        all_vulns.sort(key=lambda v: v.get("cvss_score") or 0, reverse=True)
        all_findings.sort(key=lambda f: _sev_order(f.get("severity","")), reverse=True)
        scan._risk_label = _risk_label(scan.risk_score or 0)
        scan._risk_color = _risk_color(scan.risk_score or 0)

        return render_template("scan_detail.html",
            scan=scan, hosts=hosts, all_vulns=all_vulns[:50], all_findings=all_findings,
            chart_host_risk=json.dumps({"labels":["Critical ≥9","High 7-9","Medium 4-7","Low >0","None"],
                "data":[risk_dist["critical"],risk_dist["high"],risk_dist["medium"],risk_dist["low"],risk_dist["none"]]}),
            chart_vuln_sev=json.dumps({"labels":["Critical","High","Medium","Low"],
                "data":[vuln_dist["critical"],vuln_dist["high"],vuln_dist["medium"],vuln_dist["low"]]}),
        )
    finally:
        session.close()


@bp.route("/hosts/<int:host_id>")
def host_detail(host_id):
    session = get_db_session()
    try:
        host = session.get(Host, host_id)
        if not host: return redirect(url_for("web.index"))

        scan = session.get(Scan, host.scan_id)
        ports = session.query(Port).filter_by(host_id=host_id, state="open").order_by(Port.number).all()

        ports_data = []
        all_vulns  = []
        vuln_sev   = {"critical":0,"high":0,"medium":0,"low":0}

        for p in ports:
            vulns = session.query(Vulnerability).filter_by(port_id=p.id).order_by(Vulnerability.cvss_score.desc()).all()
            max_cvss = max((v.cvss_score or 0 for v in vulns), default=0)
            ports_data.append({"port":p,"vulns":vulns,"max_cvss":max_cvss,
                "risk_color":_risk_color(max_cvss),"risk_label":_risk_label(max_cvss)})
            for v in vulns:
                sev = (v.severity.value if v.severity else "low").lower()
                if sev in vuln_sev: vuln_sev[sev]+=1
                vd = v.to_dict()
                vd.update({"port_number":p.number,"service_name":p.service_name or "?"})
                vd["_color"] = {"critical":"danger","high":"warning","medium":"info","low":"success"}.get(sev,"secondary")
                all_vulns.append(vd)

        all_vulns.sort(key=lambda v: v.get("cvss_score") or 0, reverse=True)

        findings = session.query(Finding).filter_by(host_id=host_id).all()
        for f in findings:
            f._color = {"critical":"danger","high":"warning","medium":"info","low":"success"}.get(
                f.severity.value if f.severity else "", "secondary")
        findings.sort(key=lambda f: _sev_order(f.severity.value if f.severity else ""), reverse=True)

        host._risk_label = _risk_label(host.risk_score or 0)
        host._risk_color = _risk_color(host.risk_score or 0)

        return render_template("host_detail.html",
            host=host, scan=scan, ports_data=ports_data, all_vulns=all_vulns,
            findings=findings, vuln_sev=json.dumps(vuln_sev),
        )
    finally:
        session.close()


@bp.route("/new-scan")
def new_scan():
    return render_template("new_scan.html")
