"""
scanner/orchestrator.py — Orquestador del pipeline completo de escaneo.

Coordina las tres fases del escaneo y persiste los resultados en BD:

    Fase 1 — Discovery:  Ping Sweep → lista de hosts activos
    Fase 2 — Port Scan:  Para cada host, escanear puertos TCP
    Fase 3 — Probing:    Para cada puerto abierto, detectar servicio/versión

El orquestador actualiza el estado del Scan en la BD en tiempo real
y calcula las métricas agregadas al finalizar.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Callable, List, Optional

from core.database import get_session
from core.logger import get_logger
from core.models import Host, Port, Scan, ScanStatus

from .discovery import discover_hosts, parse_target
from .port_scanner import scan_ports, parse_port_range, KNOWN_SERVICES
from .service_probe import probe_host, fingerprint_os

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════
# PROGRESO DEL ESCANEO
# ══════════════════════════════════════════════════════════════

class ScanPhase(str, PyEnum):
    """Fases del pipeline de escaneo."""
    INIT      = "init"
    DISCOVERY = "discovery"
    PORTSCAN  = "portscan"
    PROBING   = "probing"
    SAVING    = "saving"
    DONE      = "done"
    FAILED    = "failed"


@dataclass
class ScanProgress:
    """Estado de progreso para reportar a la UI o CLI."""
    phase:    ScanPhase = ScanPhase.INIT
    current:  int       = 0
    total:    int       = 0
    message:  str       = ""
    host_ip:  str       = ""

    @property
    def percent(self) -> float:
        return (self.current / self.total * 100) if self.total > 0 else 0.0

    def __str__(self) -> str:
        pct = f"{self.percent:.0f}%"
        return f"[{self.phase.value.upper()}] {pct} — {self.message}"


#: Tipo del callback de progreso: (ScanProgress) → None
ProgressCallback = Callable[[ScanProgress], None]


# ══════════════════════════════════════════════════════════════
# PELIGROSIDAD DE PUERTOS (para el motor de detección básico)
# ══════════════════════════════════════════════════════════════

#: Puertos que se marcan como peligrosos al estar expuestos
DANGEROUS_PORTS = {
    21,    # FTP — transferencia sin cifrado
    23,    # Telnet — sin cifrado
    135,   # MSRPC — vector de exploits Windows
    137,   # NetBIOS Name Service
    138,   # NetBIOS Datagram
    139,   # NetBIOS Session — SMBv1
    445,   # SMB — EternalBlue
    1433,  # MSSQL
    1521,  # Oracle DB
    2375,  # Docker API sin TLS
    3389,  # RDP — brute force
    5900,  # VNC — frecuentemente sin auth
    6379,  # Redis — sin auth por defecto
    9200,  # Elasticsearch — sin auth por defecto
    27017, # MongoDB — sin auth por defecto
}


# ══════════════════════════════════════════════════════════════
# ORQUESTADOR
# ══════════════════════════════════════════════════════════════

class ScanOrchestrator:
    """
    Orquestador del ciclo completo de escaneo de seguridad.

    Uso:
        orchestrator = ScanOrchestrator(
            scan_id    = 1,
            port_range = "1-1024",
            timeout    = 1.0,
            max_workers = 150,
        )
        completed_scan = orchestrator.run(progress_cb=my_callback)
    """

    def __init__(
        self,
        scan_id:     int,
        port_range:  str   = "1-1024",
        timeout:     float = 1.0,
        max_workers: int   = 150,
    ) -> None:
        self.scan_id     = scan_id
        self.port_range  = port_range
        self.timeout     = timeout
        self.max_workers = max_workers

        self._progress_cb: Optional[ProgressCallback] = None

    # ── API pública ──────────────────────────────────────────

    def run(
        self,
        progress_cb: Optional[ProgressCallback] = None,
    ) -> Optional[Scan]:
        """
        Ejecuta el pipeline completo de escaneo.

        El scan_id debe existir en la BD previamente (creado por create_scan).

        Args:
            progress_cb: Callback opcional para recibir actualizaciones
                         de progreso en tiempo real.

        Returns:
            El objeto Scan actualizado con todos los resultados,
            o None si el scan_id no existe.
        """
        self._progress_cb = progress_cb

        with get_session() as session:
            scan = session.get(Scan, self.scan_id)
            if not scan:
                logger.error(f"Scan {self.scan_id} no encontrado en la BD")
                return None

            logger.info(
                f"Iniciando escaneo #{scan.id} — "
                f"objetivo: {scan.target}, puertos: {scan.port_range}"
            )

            # Marcar como en ejecución
            scan.status     = ScanStatus.RUNNING
            scan.started_at = datetime.now(timezone.utc)
            session.commit()

        try:
            # ── FASE 1: DESCUBRIMIENTO ─────────────────────────
            alive_ips = self._phase_discovery()

            # ── FASE 2+3: PORT SCAN + PROBING ─────────────────
            self._phase_scan_and_probe(alive_ips)

            # ── ACTUALIZAR MÉTRICAS FINALES ────────────────────
            self._update_scan_metrics()

            # ── MARCAR COMO COMPLETADO ────────────────────────
            with get_session() as session:
                scan = session.get(Scan, self.scan_id)
                scan.status       = ScanStatus.COMPLETED
                scan.completed_at = datetime.now(timezone.utc)
                session.commit()
                result = scan.to_dict()

            self._emit_progress(ScanPhase.DONE, 1, 1, "Escaneo completado")
            logger.info(
                f"Escaneo #{self.scan_id} completado — "
                f"{result['total_hosts']} hosts, "
                f"{result['total_open_ports']} puertos, "
                f"riesgo: {result['risk_score']:.1f}"
            )

        except Exception as exc:
            logger.exception(f"Error en escaneo #{self.scan_id}: {exc}")
            with get_session() as session:
                scan = session.get(Scan, self.scan_id)
                if scan:
                    scan.status       = ScanStatus.FAILED
                    scan.completed_at = datetime.now(timezone.utc)
                    scan.notes        = f"Error: {exc}"
                    session.commit()
            self._emit_progress(ScanPhase.FAILED, 0, 1, str(exc))

        # Devolver el scan actualizado
        with get_session() as session:
            scan = session.get(Scan, self.scan_id)
            if scan:
                session.expunge(scan)
            return scan

    # ── Fases internas ───────────────────────────────────────

    def _phase_discovery(self) -> List[str]:
        """Fase 1: Descubrir hosts activos en el objetivo."""
        with get_session() as session:
            scan   = session.get(Scan, self.scan_id)
            target = scan.target

        ips = parse_target(target)
        total = len(ips)

        self._emit_progress(
            ScanPhase.DISCOVERY, 0, total,
            f"Ping Sweep en {target} ({total} IP(s))"
        )

        completed_count = [0]

        def _progress(done: int, tot: int, ip: str, alive: bool) -> None:
            completed_count[0] = done
            if alive:
                self._emit_progress(ScanPhase.DISCOVERY, done, tot, f"Activo: {ip}")
            else:
                self._emit_progress(ScanPhase.DISCOVERY, done, tot, f"Analizando...")

        if total == 1:
            # Para un único host, asumirlo activo y no hacer ping
            alive = ips
            logger.info(f"Objetivo único {target} — asumiendo activo")
        else:
            alive = discover_hosts(
                target,
                timeout     = self.timeout,
                max_workers = self.max_workers,
                progress_cb = _progress,
            )

        self._emit_progress(
            ScanPhase.DISCOVERY, total, total,
            f"Discovery completado: {len(alive)}/{total} host(s) activo(s)"
        )

        return alive

    def _phase_scan_and_probe(self, alive_ips: List[str]) -> None:
        """Fase 2+3: Para cada host activo, escanear puertos y detectar servicios."""
        total_hosts = len(alive_ips)

        for idx, ip in enumerate(alive_ips, start=1):
            self._emit_progress(
                ScanPhase.PORTSCAN, idx, total_hosts,
                f"Escaneando {ip} ({idx}/{total_hosts})"
            )
            self._scan_single_host(ip, idx, total_hosts)

    def _scan_single_host(self, ip: str, idx: int, total: int) -> None:
        """Escanea un host individual y persiste los resultados."""

        # ── Port Scan ────────────────────────────────────────
        logger.info(f"Port scan: {ip} | puertos: {self.port_range}")

        open_ports = scan_ports(
            ip,
            port_range  = self.port_range,
            timeout     = self.timeout,
            max_workers = self.max_workers,
        )

        self._emit_progress(
            ScanPhase.PROBING, idx, total,
            f"Probing {ip} — {len(open_ports)} puerto(s) abierto(s)"
        )

        # ── Service Probe ─────────────────────────────────────
        enriched_ports = []
        if open_ports:
            enriched_ports = probe_host(ip, open_ports, timeout=self.timeout + 1)

        # ── OS Fingerprinting ─────────────────────────────────
        os_name, os_confidence = fingerprint_os(ip, open_ports)

        # ── Persistir en BD ───────────────────────────────────
        self._emit_progress(ScanPhase.SAVING, idx, total, f"Guardando {ip}")
        self._save_host(ip, os_name, os_confidence, enriched_ports)

    def _save_host(
        self,
        ip:            str,
        os_name:       str,
        os_confidence: int,
        ports_data:    List[dict],
    ) -> None:
        """Persiste un host y sus puertos en la base de datos."""
        with get_session() as session:
            # Crear o actualizar el host
            existing = (
                session.query(Host)
                .filter_by(scan_id=self.scan_id, ip=ip)
                .first()
            )

            if existing:
                host = existing
            else:
                host = Host(scan_id=self.scan_id, ip=ip)
                session.add(host)

            host.os            = os_name or None
            host.os_confidence = os_confidence or None
            host.status        = "up"
            host.open_ports    = len(ports_data)

            # Calcular risk_score del host como máximo CVSS
            # (se actualiza en el módulo vuln, aquí ponemos 0)
            host.risk_score = 0.0

            session.flush()  # Obtener host.id antes de crear puertos

            # Crear los puertos
            for p in ports_data:
                existing_port = (
                    session.query(Port)
                    .filter_by(host_id=host.id, number=p["number"], protocol=p["protocol"])
                    .first()
                )

                if existing_port:
                    port_obj = existing_port
                else:
                    port_obj = Port(host_id=host.id)
                    session.add(port_obj)

                port_obj.number          = p["number"]
                port_obj.protocol        = p.get("protocol", "tcp")
                port_obj.state           = p.get("state", "open")
                port_obj.service_name    = p.get("service_name", "")[:100]
                port_obj.service_version = p.get("service_version", "")[:200]
                port_obj.service_banner  = p.get("service_banner", "")[:500]
                port_obj.cpe             = p.get("cpe", "")[:300]
                port_obj.is_dangerous    = p["number"] in DANGEROUS_PORTS

            session.commit()

        logger.debug(f"Host guardado: {ip} — {len(ports_data)} puerto(s)")

    def _update_scan_metrics(self) -> None:
        """Recalcula y actualiza las métricas agregadas del Scan."""
        with get_session() as session:
            scan = session.get(Scan, self.scan_id)
            if not scan:
                return

            hosts = session.query(Host).filter_by(scan_id=self.scan_id).all()

            scan.total_hosts      = len(hosts)
            scan.total_open_ports = sum(h.open_ports for h in hosts)
            scan.total_findings   = 0   # Se actualiza en el módulo detect

            # risk_score del scan = max de los hosts (se refinará en módulo vuln)
            risk_scores = [h.risk_score for h in hosts if h.risk_score]
            scan.risk_score = max(risk_scores) if risk_scores else 0.0

            session.commit()

        logger.debug(f"Métricas actualizadas para Scan #{self.scan_id}")

    # ── Helpers ──────────────────────────────────────────────

    def _emit_progress(
        self,
        phase:   ScanPhase,
        current: int,
        total:   int,
        message: str = "",
    ) -> None:
        """Emite un evento de progreso al callback si está configurado."""
        if not self._progress_cb:
            return
        progress = ScanProgress(
            phase   = phase,
            current = current,
            total   = total,
            message = message,
        )
        try:
            self._progress_cb(progress)
        except Exception as e:
            logger.debug(f"Error en progress callback: {e}")


# ══════════════════════════════════════════════════════════════
# FUNCIONES DE CONVENIENCIA
# ══════════════════════════════════════════════════════════════

def create_scan(
    name:       str,
    target:     str,
    port_range: str = "1-1024",
    notes:      str = "",
) -> int:
    """
    Crea un nuevo Scan en la BD y devuelve su ID.

    Args:
        name:       Nombre descriptivo de la auditoría.
        target:     IP, hostname o rango CIDR del objetivo.
        port_range: Rango de puertos a escanear.
        notes:      Notas opcionales.

    Returns:
        ID del Scan creado.
    """
    with get_session() as session:
        scan = Scan(
            name       = name,
            target     = target,
            port_range = port_range,
            status     = ScanStatus.PENDING,
            notes      = notes or "",
        )
        session.add(scan)
        session.flush()
        scan_id = scan.id
        session.commit()

    logger.info(f"Scan creado — ID: {scan_id}, target: {target}")
    return scan_id


def run_scan(
    name:        str,
    target:      str,
    port_range:  str   = "1-1024",
    timeout:     float = 1.0,
    max_workers: int   = 150,
    progress_cb: Optional[ProgressCallback] = None,
) -> Optional[Scan]:
    """
    Crea y ejecuta un escaneo completo en una sola llamada.

    Args:
        name:        Nombre de la auditoría.
        target:      IP, hostname o rango CIDR.
        port_range:  Puertos a escanear (ej: "1-1024", "common", "all").
        timeout:     Timeout por operación de red.
        max_workers: Hilos concurrentes máximos.
        progress_cb: Callback de progreso opcional.

    Returns:
        Objeto Scan completado con todos los resultados.
    """
    scan_id = create_scan(name, target, port_range)

    orchestrator = ScanOrchestrator(
        scan_id     = scan_id,
        port_range  = port_range,
        timeout     = timeout,
        max_workers = max_workers,
    )

    return orchestrator.run(progress_cb=progress_cb)
