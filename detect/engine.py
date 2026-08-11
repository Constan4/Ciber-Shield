"""
detect/engine.py — Motor de evaluación de reglas de detección.

El motor carga el catálogo de reglas de detect/rules.py,
las evalúa contra cada host de una auditoría y persiste
los hallazgos (Finding) en la base de datos.
"""

from __future__ import annotations

from typing import Dict, List

from core.database import get_session
from core.logger   import get_logger
from core.models   import Finding, Host, Port, Scan, Severity

from .rules import RULES, Rule

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════
# MOTOR DE DETECCIÓN
# ══════════════════════════════════════════════════════════════

class RuleEngine:
    """
    Evalúa el catálogo de reglas sobre los hosts escaneados
    y persiste los hallazgos en la BD.

    Uso:
        engine = RuleEngine()
        stats  = engine.evaluate_scan(scan_id=1)
        print(f"Hallazgos: {stats['findings_total']}")
    """

    def __init__(self, rules: List[Rule] | None = None) -> None:
        self.rules = rules or RULES
        logger.debug(f"RuleEngine inicializado con {len(self.rules)} regla(s)")

    # ── API pública ──────────────────────────────────────────

    def evaluate_scan(self, scan_id: int) -> Dict[str, int]:
        """
        Evalúa todas las reglas sobre todos los hosts de una auditoría.

        Args:
            scan_id: ID de la auditoría a analizar.

        Returns:
            Dict con estadísticas:
            {hosts_analyzed, findings_total, findings_critical,
             findings_high, findings_medium, findings_low}
        """
        stats = {
            "hosts_analyzed":   0,
            "findings_total":   0,
            "findings_critical": 0,
            "findings_high":    0,
            "findings_medium":  0,
            "findings_low":     0,
        }

        with get_session() as session:
            scan = session.get(Scan, scan_id)
            if not scan:
                logger.error(f"Scan #{scan_id} no encontrado")
                return stats

            hosts = session.query(Host).filter_by(scan_id=scan_id).all()
            host_ids = [h.id for h in hosts]

        logger.info(
            f"Detection engine iniciado — scan #{scan_id}, "
            f"{len(host_ids)} host(s), {len(self.rules)} regla(s)"
        )

        for host_id in host_ids:
            host_stats = self.evaluate_host(host_id)
            stats["hosts_analyzed"] += 1
            stats["findings_total"] += host_stats["total"]
            for sev in ("critical", "high", "medium", "low"):
                stats[f"findings_{sev}"] += host_stats.get(sev, 0)

        # Actualizar total de findings en el Scan
        with get_session() as session:
            scan = session.get(Scan, scan_id)
            if scan:
                scan.total_findings = stats["findings_total"]
                session.commit()

        logger.info(
            f"Detection engine completado — scan #{scan_id}: "
            f"{stats['findings_total']} hallazgo(s) en "
            f"{stats['hosts_analyzed']} host(s)"
        )

        return stats

    def evaluate_host(self, host_id: int) -> Dict[str, int]:
        """
        Evalúa todas las reglas para un host específico.

        Carga los puertos abiertos del host, ejecuta cada regla
        y persiste los Finding resultantes en la BD.

        Args:
            host_id: ID del host.

        Returns:
            Dict con el conteo de hallazgos por severidad + total.
        """
        stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

        # Cargar datos del host y sus puertos
        with get_session() as session:
            host = session.get(Host, host_id)
            if not host:
                return stats

            host_ip = host.ip

            ports_raw = (
                session.query(Port)
                .filter_by(host_id=host_id, state="open")
                .all()
            )

            # Serializar los puertos antes de cerrar la sesión
            ports_data = [
                {
                    "number":          p.number,
                    "protocol":        p.protocol,
                    "state":           p.state,
                    "service_name":    p.service_name or "",
                    "service_version": p.service_version or "",
                    "service_banner":  p.service_banner or "",
                    "is_dangerous":    p.is_dangerous,
                }
                for p in ports_raw
            ]

        if not ports_data:
            return stats

        logger.debug(
            f"Evaluando host #{host_id} ({host_ip}) — "
            f"{len(ports_data)} puerto(s), {len(self.rules)} regla(s)"
        )

        # Evaluar cada regla
        for rule in self.rules:
            evidences = rule.check(ports_data)

            for evidence in evidences:
                saved = self._save_finding(
                    host_id  = host_id,
                    rule     = rule,
                    evidence = evidence,
                )
                if saved:
                    stats["total"] += 1
                    sev = rule.severity.value.lower()
                    if sev in stats:
                        stats[sev] += 1

        # Actualizar finding_count en el Host
        with get_session() as session:
            host = session.get(Host, host_id)
            if host:
                host.finding_count = stats["total"]
                session.commit()

        if stats["total"] > 0:
            logger.debug(
                f"Host {host_ip}: {stats['total']} hallazgo(s) — "
                f"critical:{stats['critical']} high:{stats['high']} "
                f"medium:{stats['medium']} low:{stats['low']}"
            )

        return stats

    # ── Persistencia ─────────────────────────────────────────

    def _save_finding(self, host_id: int, rule: Rule, evidence: str) -> bool:
        """
        Persiste un hallazgo en la BD.

        Evita duplicados: si ya existe un Finding del mismo host
        y la misma regla, no crea uno nuevo.

        Args:
            host_id:  ID del host.
            rule:     Regla que disparó el hallazgo.
            evidence: Evidencia técnica que disparó la regla.

        Returns:
            True si se creó un nuevo Finding, False si ya existía.
        """
        with get_session() as session:
            # Evitar duplicados
            existing = (
                session.query(Finding)
                .filter_by(host_id=host_id, rule_id=rule.rule_id)
                .first()
            )
            if existing:
                return False

            finding = Finding(
                host_id     = host_id,
                rule_id     = rule.rule_id,
                rule_name   = rule.name,
                severity    = rule.severity,
                description = rule.description,
                evidence    = evidence[:1000],
                remediation = rule.remediation,
            )
            session.add(finding)
            session.commit()

        return True

    # ── Utilidades ────────────────────────────────────────────

    def test_rules(self, ports_data: List[dict]) -> List[dict]:
        """
        Evalúa todas las reglas contra una lista de puertos de prueba.

        Útil para testing y depuración sin necesitar acceso a la BD.

        Args:
            ports_data: Lista de dicts de puertos (misma estructura que en BD).

        Returns:
            Lista de dicts con los hallazgos generados.
        """
        results = []
        for rule in self.rules:
            evidences = rule.check(ports_data)
            for ev in evidences:
                results.append({
                    "rule_id":     rule.rule_id,
                    "name":        rule.name,
                    "severity":    rule.severity.value,
                    "evidence":    ev,
                    "remediation": rule.remediation,
                })
        return results


# ══════════════════════════════════════════════════════════════
# FUNCIÓN DE CONVENIENCIA
# ══════════════════════════════════════════════════════════════

def run_detection(scan_id: int) -> Dict[str, int]:
    """
    Ejecuta el motor de detección sobre una auditoría completa.

    Args:
        scan_id: ID de la auditoría.

    Returns:
        Estadísticas de los hallazgos encontrados.
    """
    engine = RuleEngine()
    return engine.evaluate_scan(scan_id)
