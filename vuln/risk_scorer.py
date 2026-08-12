"""
vuln/risk_scorer.py — Calculadora de riesgo basada en CVSS 3.1.

Niveles:
    Puerto:  max(cvss_score de sus vulnerabilidades)
    Host:    0.70 * max_port + 0.20 * mean_port + 0.10 * dangerous_bonus
    Scan:    0.60 * max_host + 0.25 * weighted_severity + 0.15 * exposure_ratio
"""

from __future__ import annotations

import statistics
from typing import Dict, List, NamedTuple, Optional

from core.database import get_session
from core.logger   import get_logger
from core.models   import Host, Port, Scan, Severity, Vulnerability

logger = get_logger(__name__)

SEVERITY_WEIGHTS = {
    "critical": 1.00, "high": 0.70,
    "medium":   0.40, "low":  0.15,
    "none":     0.00, "unknown": 0.10,
}

DANGEROUS_PORT_SCORES = {
    23: 8.0, 21: 5.0, 135: 6.0, 139: 7.0, 445: 8.5,
    1433: 7.0, 1521: 7.0, 2375: 9.0, 3389: 7.5,
    5900: 6.5, 6379: 8.0, 9200: 7.5, 27017: 8.0,
}


class ScanRiskSummary(NamedTuple):
    scan_id:        int
    risk_score:     float
    severity:       str
    total_hosts:    int
    hosts_critical: int
    hosts_high:     int
    hosts_medium:   int
    hosts_low:      int
    total_vulns:    int
    vulns_critical: int
    vulns_high:     int
    vulns_medium:   int
    vulns_low:      int
    exposed_dangerous_ports: int

    @property
    def as_dict(self):
        return self._asdict()


class RiskScorer:

    def score_port(self, port_id: int) -> float:
        """Risk score de un puerto = max CVSS de sus vulns."""
        try:
            with get_session() as session:
                vulns = session.query(Vulnerability).filter_by(port_id=port_id).all()
                port  = session.get(Port, port_id)

                if vulns:
                    scores = [v.cvss_score for v in vulns if v.cvss_score is not None]
                    score  = max(scores) if scores else 0.0
                elif port and port.number in DANGEROUS_PORT_SCORES:
                    score = DANGEROUS_PORT_SCORES[port.number]
                else:
                    score = 0.0

                return round(min(score, 10.0), 2)
        except Exception as e:
            logger.debug("score_port error port_id=" + str(port_id) + ": " + str(e))
            return 0.0

    def score_host(self, host_id: int) -> float:
        """Risk score de un host basado en sus puertos y vulnerabilidades."""
        try:
            # Obtener puertos abiertos del host
            with get_session() as session:
                ports = (session.query(Port)
                         .filter_by(host_id=host_id, state="open")
                         .all())
                port_ids     = [p.id for p in ports]
                port_numbers = [p.number for p in ports]

            if not port_ids:
                return 0.0

            # Calcular score por puerto
            port_scores = []
            for pid in port_ids:
                s = self.score_port(pid)
                if s > 0:
                    port_scores.append(s)

            if not port_scores:
                # Ningún CVE pero puede haber puertos peligrosos
                dangerous_raw = sum(
                    DANGEROUS_PORT_SCORES.get(n, 0)
                    for n in port_numbers
                    if n in DANGEROUS_PORT_SCORES
                )
                score = min(dangerous_raw * 0.3, 5.0)
            else:
                max_port  = max(port_scores)
                mean_port = statistics.mean(port_scores)
                dangerous_count  = sum(1 for n in port_numbers if n in DANGEROUS_PORT_SCORES)
                dangerous_bonus  = min(dangerous_count * 0.5, 3.0)
                score = 0.70 * max_port + 0.20 * mean_port + 0.10 * dangerous_bonus

            score = round(min(score, 10.0), 2)

            # Contar CVEs del host (query simple sin join)
            vuln_count = 0
            try:
                with get_session() as session:
                    for pid in port_ids:
                        vuln_count += session.query(Vulnerability).filter_by(port_id=pid).count()
            except Exception:
                pass

            # Actualizar host en BD
            try:
                with get_session() as session:
                    host = session.get(Host, host_id)
                    if host:
                        host.risk_score = score
                        host.vuln_count = vuln_count
                        session.commit()
            except Exception as e:
                logger.debug("Error actualizando host risk_score: " + str(e))

            logger.debug("Host #" + str(host_id) + " risk_score = " + str(score))
            return score

        except Exception as e:
            logger.debug("score_host error host_id=" + str(host_id) + ": " + str(e))
            return 0.0

    def score_scan(self, scan_id: int) -> ScanRiskSummary:
        """Risk score global de una auditoria."""
        try:
            with get_session() as session:
                scan = session.get(Scan, scan_id)
                if not scan:
                    return self._empty_summary(scan_id)
                hosts = session.query(Host).filter_by(scan_id=scan_id).all()
                host_ids = [h.id for h in hosts]

            if not host_ids:
                return self._empty_summary(scan_id)

            # Calcular scores de todos los hosts
            host_scores = [self.score_host(hid) for hid in host_ids]

            # Recopilar severidades de CVEs (queries simples)
            vuln_sev_list = []
            with get_session() as session:
                for hid in host_ids:
                    port_ids = [p.id for p in session.query(Port).filter_by(host_id=hid).all()]
                    for pid in port_ids:
                        vulns = session.query(Vulnerability).filter_by(port_id=pid).all()
                        for v in vulns:
                            sev = v.severity.value if v.severity else "low"
                            vuln_sev_list.append(sev)

            # Metricas de distribucion
            def count_sev(level):
                return sum(1 for s in vuln_sev_list if s == level)

            max_host     = max(host_scores) if host_scores else 0.0
            total_vulns  = len(vuln_sev_list)

            if total_vulns > 0:
                weighted_sum = sum(SEVERITY_WEIGHTS.get(s, 0.1) for s in vuln_sev_list)
                weighted_idx = min(weighted_sum / total_vulns * 10, 10.0)
            else:
                weighted_idx = 0.0

            hosts_exposed  = sum(1 for s in host_scores if s > 0)
            exposure_ratio = (hosts_exposed / len(host_scores) * 10) if host_scores else 0.0

            global_score = (0.60 * max_host + 0.25 * weighted_idx + 0.15 * exposure_ratio)
            global_score = round(min(global_score, 10.0), 2)
            severity     = Severity.from_cvss(global_score).value.upper()

            # Contar puertos peligrosos
            dangerous_total = 0
            try:
                with get_session() as session:
                    for hid in host_ids:
                        dangerous_total += (session.query(Port)
                                            .filter_by(host_id=hid, state="open", is_dangerous=True)
                                            .count())
            except Exception:
                pass

            summary = ScanRiskSummary(
                scan_id        = scan_id,
                risk_score     = global_score,
                severity       = severity,
                total_hosts    = len(host_ids),
                hosts_critical = sum(1 for s in host_scores if s >= 9.0),
                hosts_high     = sum(1 for s in host_scores if 7.0 <= s < 9.0),
                hosts_medium   = sum(1 for s in host_scores if 4.0 <= s < 7.0),
                hosts_low      = sum(1 for s in host_scores if 0 < s < 4.0),
                total_vulns    = total_vulns,
                vulns_critical = count_sev("critical"),
                vulns_high     = count_sev("high"),
                vulns_medium   = count_sev("medium"),
                vulns_low      = count_sev("low"),
                exposed_dangerous_ports = dangerous_total,
            )

            # Actualizar Scan en BD
            try:
                with get_session() as session:
                    scan = session.get(Scan, scan_id)
                    if scan:
                        scan.risk_score  = global_score
                        scan.total_vulns = total_vulns
                        session.commit()
            except Exception as e:
                logger.debug("Error actualizando scan risk_score: " + str(e))

            logger.info(
                "Scan #" + str(scan_id) + " risk_score=" + str(global_score) +
                " (" + severity + ") — " + str(total_vulns) + " CVE(s)"
            )
            return summary

        except Exception as e:
            logger.debug("score_scan error: " + str(e))
            return self._empty_summary(scan_id)

    @staticmethod
    def _empty_summary(scan_id: int) -> ScanRiskSummary:
        return ScanRiskSummary(
            scan_id=scan_id, risk_score=0.0, severity="NONE",
            total_hosts=0, hosts_critical=0, hosts_high=0,
            hosts_medium=0, hosts_low=0, total_vulns=0,
            vulns_critical=0, vulns_high=0, vulns_medium=0, vulns_low=0,
            exposed_dangerous_ports=0,
        )


def run_vuln_analysis(scan_id: int) -> ScanRiskSummary:
    """Correlación CVE + risk scoring completo."""
    from .correlator import CVECorrelator

    logger.info("Iniciando analisis de vulnerabilidades — scan #" + str(scan_id))

    correlator = CVECorrelator()
    corr_stats = correlator.correlate_scan(scan_id)
    logger.info(
        "Correlacion completada — " +
        str(corr_stats["cves_found"]) + " CVE(s) en " +
        str(corr_stats["ports_with_vulns"]) + "/" +
        str(corr_stats["ports_analyzed"]) + " puerto(s)"
    )

    scorer  = RiskScorer()
    summary = scorer.score_scan(scan_id)

    logger.info(
        "Risk scoring completado — " +
        str(summary.risk_score) + "/10 (" + summary.severity + ")"
    )
    return summary
