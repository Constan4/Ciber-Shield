"""
vuln — Motor de vulnerabilidades de Ciber-Shield.

Módulos:
    nvd_client.py  → Cliente NVD API v2.0 con caché y rate limiting
    correlator.py  → Correlación servicio/versión → CVEs
    risk_scorer.py → Puntuación de riesgo CVSS-based (puerto/host/scan)
"""

from .nvd_client  import NVDClient
from .correlator  import CVECorrelator
from .risk_scorer import RiskScorer, ScanRiskSummary, run_vuln_analysis

__all__ = [
    "NVDClient",
    "CVECorrelator",
    "RiskScorer",
    "ScanRiskSummary",
    "run_vuln_analysis",
]
