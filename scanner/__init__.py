"""
scanner — Módulo de escaneo de red de Ciber-Shield.

Pipeline de tres fases:
    1. discovery.py     → Ping Sweep (hosts activos)
    2. port_scanner.py  → TCP port scanning (puertos abiertos)
    3. service_probe.py → Service/version detection (fingerprinting)
    4. orchestrator.py  → Coordina el pipeline + persistencia en BD
"""

from .discovery     import discover_hosts, parse_target
from .port_scanner  import scan_ports, parse_port_range, PortResult, KNOWN_SERVICES
from .service_probe import probe_host, fingerprint_os, probe_service
from .orchestrator  import (
    ScanOrchestrator, ScanPhase, ScanProgress,
    create_scan, run_scan,
)

__all__ = [
    "discover_hosts", "parse_target",
    "scan_ports", "parse_port_range", "PortResult", "KNOWN_SERVICES",
    "probe_host", "fingerprint_os", "probe_service",
    "ScanOrchestrator", "ScanPhase", "ScanProgress",
    "create_scan", "run_scan",
]
