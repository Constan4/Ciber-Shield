"""
vuln/risk_scorer.py — Calculadora de riesgo de seguridad basada en CVSS 3.1.

Calcula puntuaciones de riesgo a tres niveles:

    Puerto (Port):
        risk_score = max(cvss_score de sus vulnerabilidades)
        Si tiene puertos peligrosos sin CVEs → puntuación base de 3.0

    Host:
        risk_score = 0.70 * max_port_score
                   + 0.20 * mean_port_score
                   + 0.10 * dangerous_port_bonus
        Capped a 10.0

    Scan (auditoría completa):
        risk_score = 0.60 * max_host_score
                   + 0.25 * weighted_severity_index
                   + 0.15 * exposure_ratio
        Capped a 10.0

Tras el cálculo, se actualizan los campos risk_score en la BD.
"""

from __future__ import annotations

import statistics
from typing import Dict, List, NamedTuple, Optional

from core.database import get_session
from core.logger import get_logger
from core.models import Host, Port, Scan, Severity, Vulnerability

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════

#: Peso de cada nivel de severidad para el índice ponderado
SEVERITY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 1.00,
    "HIGH":     0.70,
    "MEDIUM":   0.40,
    "LOW":      0.15,
    "NONE":     0.00,
    "UNKNOWN":  0.10,
}

#: Bonus de riesgo (0–10) para puertos peligrosos sin CVE conocido
DANGEROUS_PORT_SCORES: Dict[int, float] = {
    23:    8.0,   # Telnet — tráfico sin cifrar
    21:    5.0,   # FTP — sin cifrar
    135:   6.0,   # MSRPC
    139:   7.0,   # NetBIOS SMBv1
    445:   8.5,   # SMB — EternalBlue familia
    1433:  7.0,   # MSSQL
    1521:  7.0,   # Oracle DB
    2375:  9.0,   # Docker API sin TLS
    3389:  7.5,   # RDP
    5900:  6.5,   # VNC (frecuentemente sin auth)
    6379:  8.0,   # Redis sin auth por defecto
    9200:  7.5,   # Elasticsearch sin auth
    27017: 8.0,   # MongoDB sin auth
}


# ══════════════════════════════════════════════════════════════
# DTOs DE RESULTADO
# ══════════════════════════════════════════════════════════════

class ScanRiskSummary(NamedTuple):
    """Resumen completo del análisis de riesgo de una auditoría."""
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
    def as_dict(self) -> dict:
        return self._asdict()


# ══════════════════════════════════════════════════════════════
# MOTOR DE PUNTUACIÓN
# ══════════════════════════════════════════════════════════════

class RiskScorer:
    """
    Calcula y actualiza las puntuaciones de riesgo en la base de datos.

    Uso:
        scorer = RiskScorer()
        summary = scorer.score_scan(scan_id=1)
        print(f"Riesgo global: {summary.risk_score:.1f}/10")
    """

    # ── Nivel Puerto ─────────────────────────────────────────

    def score_port(self, port_id: int) -> float:
        """
        Calcula el risk_score de un puerto individual.

        El score es el máximo CVSS de sus vulnerabilidades.
        Si es un puerto peligroso sin vulns, se asigna un score base.

        Args:
            port_id: ID del puerto.

        Returns:
            Puntuación de riesgo 0.0–10.0.
        """
        with get_session() as session:
            port = session.get(Port, port_id)
            if not port:
                return 0.0

            vulns = (
                session.query(Vulnerability)
                .filter_by(port_id=port_id)
                .all()
            )

            if vulns:
                scores = [v.cvss_score for v in vulns if v.cvss_score is not None]
                score  = max(scores) if scores else 0.0
            elif port.number in DANGEROUS_PORT_SCORES:
                # Puerto peligroso expuesto sin CVEs conocidos aún
                score = DANGEROUS_PORT_SCORES[port.number]
            else:
                score = 0.0

            score = round(min(score, 10.0), 2)
            port.risk_score = score  # Actualizar si el modelo lo tiene
            session.commit()

        return score

    # ── Nivel Host ───────────────────────────────────────────

    def score_host(self, host_id: int) -> float:
        """
        Calcula el risk_score de un host basado en sus puertos.

        Fórmula:
            score = 0.70 * max_port
                  + 0.20 * mean_port
                  + 0.10 * dangerous_bonus

        Args:
            host_id: ID del host.

        Returns:
            Puntuación de riesgo 0.0–10.0.
        """
        with get_session() as session:
            host = session.get(Host, host_id)
            if not host:
                return 0.0

            ports = (
                session.query(Port)
                .filter_by(host_id=host_id, state="open")
                .all()
            )

        if not ports:
            return 0.0

        # Calcular scores individuales de puertos
        port_scores = [self.score_port(p.id) for p in ports]
        port_scores = [s for s in port_scores if s > 0]

        if not port_scores:
            return 0.0

        max_port  = max(port_scores)
        mean_port = statistics.mean(port_scores)

        # Bonus por puertos peligrosos expuestos
        dangerous_count = sum(
            1 for p in ports if p.number in DANGEROUS_PORT_SCORES
        )
        dangerous_bonus = min(dangerous_count * 0.5, 3.0)

        score = (
            0.70 * max_port
            + 0.20 * mean_port
            + 0.10 * dangerous_bonus
        )
        score = round(min(score, 10.0), 2)

        # Actualizar en BD
        with get_session() as session:
            host = session.get(Host, host_id)
            if host:
                host.risk_score    = score
                host.vuln_count    = sum(
                    session.query(Vulnerability)
                    .join(Port)
                    .filter(Port.host_id == host_id)
                    .count()
                    for _ in [1]
                )
                host.finding_count = 0  # Se actualiza en detect/
                session.commit()

        logger.debug(f"Host #{host_id} risk_score = {score:.2f}")
        return score

    # ── Nivel Scan ───────────────────────────────────────────

    def score_scan(self, scan_id: int) -> ScanRiskSummary:
        """
        Calcula el risk_score global de una auditoría y devuelve el resumen completo.

        Fórmula:
            score = 0.60 * max_host_score
                  + 0.25 * weighted_severity_index
                  + 0.15 * exposure_ratio

        Args:
            scan_id: ID de la auditoría.

        Returns:
            ScanRiskSummary con todas las métricas calculadas.
        """
        with get_session() as session:
            scan = session.get(Scan, scan_id)
            if not scan:
                return self._empty_summary(scan_id)

            hosts = (
                session.query(Host)
                .filter_by(scan_id=scan_id)
                .all()
            )
            host_ids = [h.id for h in hosts]

        if not host_ids:
            return self._empty_summary(scan_id)

        # ── Calcular scores de todos los hosts ────────────────
        host_scores = [self.score_host(hid) for hid in host_ids]
        max_host    = max(host_scores) if host_scores else 0.0
        mean_host   = statistics.mean(host_scores) if host_scores else 0.0

        # ── Recopilar vulnerabilidades para métricas ──────────
        vuln_severities: List[str] = []

        with get_session() as session:
            for host_id in host_ids:
                ports = session.query(Port).filter_by(host_id=host_id).all()
                for port in ports:
                    vulns = session.query(Vulnerability).filter_by(port_id=port.id).all()
                    for v in vulns:
                        sev = v.severity.value.upper() if v.severity else "UNKNOWN"
                        vuln_severities.append(sev)

        # Índice ponderado de severidad (0–10)
        if vuln_severities:
            weighted_sum = sum(SEVERITY_WEIGHTS.get(s, 0.1) for s in vuln_severities)
            weighted_idx = min(weighted_sum / len(vuln_severities) * 10, 10.0)
        else:
            weighted_idx = 0.0

        # Ratio de exposición: hosts con score > 0 / total hosts
        hosts_exposed   = sum(1 for s in host_scores if s > 0)
        exposure_ratio  = (hosts_exposed / len(host_scores)) * 10 if host_scores else 0.0

        # ── Score global ──────────────────────────────────────
        global_score = (
            0.60 * max_host
            + 0.25 * weighted_idx
            + 0.15 * exposure_ratio
        )
        global_score = round(min(global_score, 10.0), 2)

        severity = Severity.from_cvss(global_score).value.upper()

        # ── Contar por severidad ──────────────────────────────
        def count_sev(level: str) -> int:
            return vuln_severities.count(level)

        # Clasificar hosts por severidad de su risk_score
        def host_sev_count(lo: float, hi: float) -> int:
            return sum(1 for s in host_scores if lo <= s <= hi)

        summary = ScanRiskSummary(
            scan_id        = scan_id,
            risk_score     = global_score,
            severity       = severity,
            total_hosts    = len(host_ids),
            hosts_critical = host_sev_count(9.0, 10.0),
            hosts_high     = host_sev_count(7.0, 8.9),
            hosts_medium   = host_sev_count(4.0, 6.9),
            hosts_low      = host_sev_count(0.1, 3.9),
            total_vulns    = len(vuln_severities),
            vulns_critical = count_sev("CRITICAL"),
            vulns_high     = count_sev("HIGH"),
            vulns_medium   = count_sev("MEDIUM"),
            vulns_low      = count_sev("LOW"),
            exposed_dangerous_ports = self._count_dangerous_ports(host_ids),
        )

        # ── Actualizar Scan en BD ─────────────────────────────
        with get_session() as session:
            scan = session.get(Scan, scan_id)
            if scan:
                scan.risk_score  = global_score
                scan.total_vulns = len(vuln_severities)
                session.commit()

        logger.info(
            f"Scan #{scan_id} risk_score = {global_score:.2f} "
            f"({severity}) — {len(vuln_severities)} CVE(s)"
        )

        return summary

    # ── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _count_dangerous_ports(host_ids: List[int]) -> int:
        """Cuenta el total de puertos peligrosos abiertos en los hosts."""
        total = 0
        with get_session() as session:
            for host_id in host_ids:
                total += (
                    session.query(Port)
                    .filter(
                        Port.host_id    == host_id,
                        Port.state      == "open",
                        Port.is_dangerous == True,
                    )
                    .count()
                )
        return total

    @staticmethod
    def _empty_summary(scan_id: int) -> ScanRiskSummary:
        """Devuelve un ScanRiskSummary vacío (sin datos)."""
        return ScanRiskSummary(
            scan_id=scan_id, risk_score=0.0, severity="NONE",
            total_hosts=0, hosts_critical=0, hosts_high=0,
            hosts_medium=0, hosts_low=0, total_vulns=0,
            vulns_critical=0, vulns_high=0, vulns_medium=0, vulns_low=0,
            exposed_dangerous_ports=0,
        )


# ══════════════════════════════════════════════════════════════
# FUNCIÓN DE CONVENIENCIA
# ══════════════════════════════════════════════════════════════

def run_vuln_analysis(scan_id: int) -> ScanRiskSummary:
    """
    Ejecuta el análisis completo de vulnerabilidades para una auditoría:
        1. Correlación CVE (NVD API)
        2. Cálculo de risk scores (puerto → host → scan)

    Args:
        scan_id: ID de la auditoría a analizar.

    Returns:
        ScanRiskSummary con el resumen completo.
    """
    from .correlator import CVECorrelator

    logger.info(f"Iniciando análisis de vulnerabilidades — scan #{scan_id}")

    # Fase 1: Correlación CVE
    correlator = CVECorrelator()
    corr_stats = correlator.correlate_scan(scan_id)
    logger.info(
        f"Correlación completada — "
        f"{corr_stats['cves_found']} CVE(s) en "
        f"{corr_stats['ports_with_vulns']}/{corr_stats['ports_analyzed']} puerto(s)"
    )

    # Fase 2: Risk scoring
    scorer  = RiskScorer()
    summary = scorer.score_scan(scan_id)

    logger.info(
        f"Risk scoring completado — "
        f"Score global: {summary.risk_score:.1f}/10 ({summary.severity})"
    )

    return summary
