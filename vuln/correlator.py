"""
vuln/correlator.py — Correlación de servicios escaneados con CVEs de la NVD.

Para cada puerto abierto con servicio identificado, este módulo:
    1. Construye los términos de búsqueda óptimos (CPE si existe, keyword si no).
    2. Consulta la NVD API (con caché) para obtener CVEs relevantes.
    3. Filtra falsos positivos por relevancia del nombre del servicio.
    4. Persiste las vulnerabilidades en la tabla 'vulnerabilities' de la BD.
    5. Devuelve un resumen de la correlación.
"""

import json
import re
from typing import Dict, List, Optional, Tuple

from core.database import get_session
from core.logger import get_logger
from core.models import Host, Port, Scan, Severity, Vulnerability

from .nvd_client import NVDClient

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════
# TÉRMINOS DE BÚSQUEDA POR SERVICIO
# ══════════════════════════════════════════════════════════════

#: Mapeo: nombre de servicio → término de búsqueda en NVD
SERVICE_KEYWORDS: Dict[str, str] = {
    "http":           "apache httpd",
    "https":          "apache httpd",
    "http-proxy":     "nginx",
    "https-alt":      "nginx",
    "ftp":            "ftp server",
    "ftp-data":       "ftp server",
    "ssh":            "openssh",
    "smtp":           "postfix exim sendmail",
    "smtps":          "postfix exim",
    "submission":     "postfix",
    "pop3":           "dovecot pop3",
    "imap":           "dovecot imap",
    "imaps":          "dovecot imap",
    "pop3s":          "dovecot pop3",
    "telnet":         "telnet server",
    "netbios-ssn":    "windows smb netbios",
    "smb":            "windows smb",
    "msrpc":          "windows rpc",
    "rdp":            "remote desktop protocol windows",
    "mysql":          "mysql mariadb",
    "postgresql":     "postgresql",
    "mssql":          "microsoft sql server",
    "oracle-db":      "oracle database",
    "mongodb":        "mongodb",
    "redis":          "redis",
    "elasticsearch":  "elasticsearch",
    "ldap":           "openldap",
    "ldaps":          "openldap",
    "vnc":            "vnc server",
    "docker":         "docker engine",
    "docker-tls":     "docker engine",
    "kubernetes":     "kubernetes",
}

#: Número máximo de CVEs a correlacionar por puerto
MAX_CVES_PER_PORT = 10

#: Puertos para los que no tiene sentido buscar CVEs (genéricos/no identificados)
SKIP_SERVICES = {"unknown", "", "ftp-data", "netbios-ns", "netbios-dgm",
                 "dhcp", "dhcp-client", "ntp", "dns", "syslog", "snmptrap"}


# ══════════════════════════════════════════════════════════════
# CORRELADOR
# ══════════════════════════════════════════════════════════════

class CVECorrelator:
    """
    Correlaciona los servicios detectados durante el escaneo
    con vulnerabilidades conocidas de la NVD.

    Uso:
        correlator = CVECorrelator()
        total = correlator.correlate_scan(scan_id=1)
        print(f"Encontrados {total} CVEs")
    """

    def __init__(self, nvd_client: Optional[NVDClient] = None) -> None:
        self.nvd = nvd_client or NVDClient()

    # ── API pública ──────────────────────────────────────────

    def correlate_scan(self, scan_id: int) -> Dict[str, int]:
        """
        Correlaciona todos los puertos de una auditoría con CVEs.

        Itera por cada host y cada puerto abierto, busca CVEs
        en la NVD y los persiste en la BD.

        Args:
            scan_id: ID de la auditoría a analizar.

        Returns:
            Dict con estadísticas: {ports_analyzed, cves_found, ports_with_vulns}
        """
        stats = {"ports_analyzed": 0, "cves_found": 0, "ports_with_vulns": 0}

        with get_session() as session:
            scan = session.get(Scan, scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} no encontrado")
                return stats

            hosts = session.query(Host).filter_by(scan_id=scan_id).all()
            host_ids = [h.id for h in hosts]

        logger.info(
            f"Correlación CVE iniciada — scan #{scan_id}, "
            f"{len(host_ids)} host(s)"
        )

        for host_id in host_ids:
            host_stats = self.correlate_host(host_id)
            stats["ports_analyzed"]   += host_stats["ports_analyzed"]
            stats["cves_found"]       += host_stats["cves_found"]
            stats["ports_with_vulns"] += host_stats["ports_with_vulns"]

        # Actualizar total de vulns en el Scan
        with get_session() as session:
            scan = session.get(Scan, scan_id)
            if scan:
                scan.total_vulns = stats["cves_found"]
                session.commit()

        logger.info(
            f"Correlación CVE completada — scan #{scan_id}: "
            f"{stats['cves_found']} CVE(s) en "
            f"{stats['ports_with_vulns']}/{stats['ports_analyzed']} puerto(s)"
        )

        return stats

    def correlate_host(self, host_id: int) -> Dict[str, int]:
        """
        Correlaciona todos los puertos de un host con CVEs.

        Args:
            host_id: ID del host a analizar.

        Returns:
            Dict con estadísticas de la correlación del host.
        """
        stats = {"ports_analyzed": 0, "cves_found": 0, "ports_with_vulns": 0}

        with get_session() as session:
            host  = session.get(Host, host_id)
            if not host:
                return stats
            host_ip = host.ip
            ports = session.query(Port).filter_by(
                host_id=host_id, state="open"
            ).all()
            port_data = [(p.id, p.number, p.service_name, p.service_version, p.cpe)
                         for p in ports]

        for port_id, port_num, svc_name, svc_version, cpe in port_data:
            stats["ports_analyzed"] += 1

            if svc_name in SKIP_SERVICES:
                logger.debug(f"Saltando puerto {port_num} ({svc_name}) — sin búsqueda CVE")
                continue

            cves = self.correlate_port_data(
                port_num    = port_num,
                service_name = svc_name,
                service_version = svc_version,
                cpe         = cpe,
            )

            if cves:
                saved = self._save_vulnerabilities(port_id, cves)
                stats["cves_found"]       += len(saved)
                stats["ports_with_vulns"] += 1
                logger.debug(
                    f"Puerto {host_ip}:{port_num} ({svc_name}) → "
                    f"{len(saved)} CVE(s) guardados"
                )

            # Actualizar vuln_count en el puerto
            with get_session() as session:
                port_obj = session.get(Port, port_id)
                if port_obj:
                    port_obj_vulns = (
                        session.query(Vulnerability)
                        .filter_by(port_id=port_id)
                        .count()
                    )
                    session.commit()

        return stats

    def correlate_port_data(
        self,
        port_num:        int,
        service_name:    str,
        service_version: str,
        cpe:             str,
    ) -> List[dict]:
        """
        Busca CVEs para un conjunto de datos de puerto.

        Estrategia de búsqueda:
            1. CPE (más preciso) si está disponible y el puerto tiene versión
            2. Keyword con nombre+versión si hay versión conocida
            3. Keyword con nombre genérico del servicio

        Args:
            port_num:        Número de puerto.
            service_name:    Nombre del servicio (ej: "http").
            service_version: Versión detectada (ej: "Apache/2.4.49").
            cpe:             CPE si está disponible.

        Returns:
            Lista de dicts CVE normalizados (sin duplicados, sin falsos positivos).
        """
        cves: List[dict] = []
        seen_ids: set = set()

        # ── Estrategia 1: por CPE ─────────────────────────────
        if cpe and ":" in cpe and service_version:
            logger.debug(f"Búsqueda por CPE: {cpe}")
            results = self.nvd.search_by_cpe(cpe, max_results=MAX_CVES_PER_PORT)
            for cve in results:
                if cve["cve_id"] not in seen_ids:
                    cves.append(cve)
                    seen_ids.add(cve["cve_id"])

        # ── Estrategia 2: por keyword con versión ─────────────
        if service_version and len(cves) < MAX_CVES_PER_PORT:
            keyword = self._build_keyword(service_name, service_version)
            if keyword:
                logger.debug(f"Búsqueda por keyword (con versión): '{keyword}'")
                results = self.nvd.search_by_keyword(
                    keyword, max_results=MAX_CVES_PER_PORT
                )
                for cve in results:
                    if cve["cve_id"] not in seen_ids:
                        cves.append(cve)
                        seen_ids.add(cve["cve_id"])

        # ── Estrategia 3: por keyword genérico ───────────────
        if not cves and service_name not in SKIP_SERVICES:
            keyword = SERVICE_KEYWORDS.get(service_name, service_name)
            if keyword and keyword != service_name:
                logger.debug(f"Búsqueda por keyword (genérico): '{keyword}'")
                results = self.nvd.search_by_keyword(
                    keyword, max_results=MAX_CVES_PER_PORT
                )
                for cve in results:
                    if (cve["cve_id"] not in seen_ids
                            and self._is_relevant(cve, service_name)):
                        cves.append(cve)
                        seen_ids.add(cve["cve_id"])

        # Ordenar por CVSS y limitar
        cves.sort(key=lambda c: c.get("cvss_score") or 0.0, reverse=True)
        return cves[:MAX_CVES_PER_PORT]

    # ── Persistencia ─────────────────────────────────────────

    def _save_vulnerabilities(
        self,
        port_id: int,
        cves:    List[dict],
    ) -> List[Vulnerability]:
        """
        Persiste la lista de CVEs como objetos Vulnerability en la BD.

        Evita duplicados comprobando (port_id, cve_id).

        Args:
            port_id: ID del puerto al que pertenecen las vulnerabilidades.
            cves:    Lista de dicts CVE normalizados (de NVDClient).

        Returns:
            Lista de objetos Vulnerability creados o actualizados.
        """
        saved: List[Vulnerability] = []

        with get_session() as session:
            for cve_data in cves:
                cve_id = cve_data.get("cve_id", "")
                if not cve_id:
                    continue

                # Evitar duplicados
                existing = (
                    session.query(Vulnerability)
                    .filter_by(port_id=port_id, cve_id=cve_id)
                    .first()
                )
                if existing:
                    saved.append(existing)
                    continue

                score    = cve_data.get("cvss_score")
                severity = Severity.from_cvss(score)

                vuln = Vulnerability(
                    port_id     = port_id,
                    cve_id      = cve_id,
                    cvss_score  = score,
                    severity    = severity,
                    vector      = cve_data.get("vector", "")[:200],
                    description = cve_data.get("description", "")[:1000],
                    references  = json.dumps(cve_data.get("references", [])),
                )

                # Fecha de publicación
                published = cve_data.get("published")
                if published:
                    vuln.published = published.replace(tzinfo=None) if hasattr(published, 'replace') else published

                session.add(vuln)
                saved.append(vuln)

            session.commit()

        return saved

    # ── Helpers de búsqueda ───────────────────────────────────

    def _build_keyword(self, service_name: str, service_version: str) -> str:
        """
        Construye el keyword más preciso para la búsqueda en NVD.

        Combina el nombre limpio del servicio con la versión detectada.
        Ejemplo: service_name="http", version="Apache/2.4.49" → "apache 2.4.49"
        """
        # Limpiar la versión de prefijos
        version_clean = re.sub(
            r"^(Apache|nginx|OpenSSH|vsftpd|IIS|Postfix)[_/\s]+",
            "",
            service_version,
            flags=re.I,
        ).strip()

        # Obtener el nombre de búsqueda del servicio
        base = SERVICE_KEYWORDS.get(service_name, service_name)

        if version_clean and re.search(r"\d", version_clean):
            # Extraer solo el número de versión si hay texto extra
            version_num = re.search(r"[\d.]+", version_clean)
            if version_num:
                return f"{base} {version_num.group()}".strip()

        return base if base != service_name else service_name

    @staticmethod
    def _is_relevant(cve: dict, service_name: str) -> bool:
        """
        Comprueba si un CVE es relevante para el servicio dado.

        Filtra falsos positivos básicos verificando que la descripción
        del CVE menciona el tipo de servicio.

        Args:
            cve:          Dict CVE normalizado.
            service_name: Nombre del servicio (ej: "http", "ssh").

        Returns:
            True si el CVE parece relevante para el servicio.
        """
        description = (cve.get("description") or "").lower()
        if not description:
            return False

        # Palabras clave de relevancia por tipo de servicio
        relevance_map = {
            "http":       ["http", "web", "apache", "nginx", "iis"],
            "https":      ["http", "https", "web", "tls", "ssl"],
            "ftp":        ["ftp", "file transfer"],
            "ssh":        ["ssh", "openssh", "secure shell"],
            "smtp":       ["smtp", "mail", "email", "postfix", "exim"],
            "rdp":        ["rdp", "remote desktop", "terminal service"],
            "mysql":      ["mysql", "mariadb", "sql"],
            "postgresql": ["postgresql", "postgres"],
            "redis":      ["redis"],
            "mongodb":    ["mongodb", "mongo"],
            "elasticsearch": ["elasticsearch", "elastic"],
            "smb":        ["smb", "samba", "cifs", "netbios"],
            "ldap":       ["ldap", "active directory", "openldap"],
            "vnc":        ["vnc", "virtual network computing"],
        }

        keywords = relevance_map.get(service_name, [service_name])
        return any(kw in description for kw in keywords)
