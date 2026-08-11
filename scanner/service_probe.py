"""
scanner/service_probe.py — Detección de servicios, versiones y OS fingerprinting.

Para cada puerto abierto detectado por el port scanner, este módulo:
  1. Envía sondas específicas por protocolo para forzar el banner.
  2. Extrae la versión del servicio mediante patrones regex.
  3. Construye el CPE (Common Platform Enumeration) para buscar CVEs.
  4. Infiere el sistema operativo por TTL ICMP o banners SSH/HTTP.
"""

import re
import socket
import subprocess
import platform
from typing import Dict, List, Optional, Tuple

from core.logger import get_logger
from .port_scanner import PortResult, KNOWN_SERVICES

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════
# SONDAS POR PROTOCOLO
# ══════════════════════════════════════════════════════════════

#: Bytes a enviar al conectar, indexados por nombre de servicio
SERVICE_PROBES: Dict[str, bytes] = {
    "http":       b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: Ciber-Shield\r\n\r\n",
    "https":      b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: Ciber-Shield\r\n\r\n",
    "http-proxy": b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: Ciber-Shield\r\n\r\n",
    "https-alt":  b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: Ciber-Shield\r\n\r\n",
    "http-alt":   b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: Ciber-Shield\r\n\r\n",
    "smtp":       b"EHLO ciber-shield.local\r\n",
    "smtps":      b"EHLO ciber-shield.local\r\n",
    "submission": b"EHLO ciber-shield.local\r\n",
    "ftp":        b"",        # Banner automático en conexión
    "ftp-data":   b"",
    "ssh":        b"",        # Banner automático SSH-2.0-...
    "pop3":       b"",
    "imap":       b"",
    "redis":      b"PING\r\n",
    "mysql":      b"",        # Handshake automático
    "mongodb":    b"",
    "ldap":       b"",
    "netbios-ssn":b"",
    "smb":        b"",
    "rdp":        b"",
    "vnc":        b"",
    "dns":        b"\x00\x1e\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
}

#: Timeout específico por protocolo lento
SLOW_SERVICES = {"mysql", "mongodb", "postgresql", "oracle-db", "mssql", "rdp", "vnc"}


# ══════════════════════════════════════════════════════════════
# PATRONES DE EXTRACCIÓN DE VERSIÓN
# ══════════════════════════════════════════════════════════════

# Cada entrada: (patrón_compilado, nombre_software)
VERSION_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # HTTP servers
    (re.compile(r"Apache/([\d.]+)", re.I),            "apache_httpd"),
    (re.compile(r"nginx/([\d.]+)", re.I),              "nginx"),
    (re.compile(r"Microsoft-IIS/([\d.]+)", re.I),      "iis"),
    (re.compile(r"LiteSpeed/([\d.]+)", re.I),          "litespeed"),
    (re.compile(r"lighttpd/([\d.]+)", re.I),           "lighttpd"),
    # SSH
    (re.compile(r"SSH-[\d.]+-OpenSSH_([\d.p]+)", re.I),"openssh"),
    (re.compile(r"SSH-[\d.]+-(.+?)[\r\n]", re.I),      "ssh"),
    # FTP
    (re.compile(r"220.*?vsftpd\s+([\d.]+)", re.I),    "vsftpd"),
    (re.compile(r"220.*?FileZilla\s+([\d.]+)", re.I), "filezilla_server"),
    (re.compile(r"220.*?ProFTPD\s+([\d.]+)", re.I),   "proftpd"),
    # Mail
    (re.compile(r"220.*?Postfix", re.I),               "postfix"),
    (re.compile(r"220.*?Exim\s+([\d.]+)", re.I),       "exim"),
    (re.compile(r"220.*?Microsoft.*?ESMTP", re.I),     "exchange"),
    # Databases
    (re.compile(r"MySQL\s+([\d.]+)", re.I),            "mysql"),
    (re.compile(r"([\d.]+)-MariaDB", re.I),            "mariadb"),
    (re.compile(r"PostgreSQL\s+([\d.]+)", re.I),       "postgresql"),
    # Redis
    (re.compile(r"\+OK", re.I),                        "redis"),
    # Generic version fallback
    (re.compile(r"/([\d]+\.[\d]+\.?[\d]*)", re.I),     None),
]


# ══════════════════════════════════════════════════════════════
# SONDEO DE UN SERVICIO
# ══════════════════════════════════════════════════════════════

def probe_service(
    ip: str,
    port: int,
    service_hint: str = "",
    timeout: float    = 2.0,
) -> Tuple[str, str, str]:
    """
    Sondea un puerto para identificar el servicio, la versión y el banner.

    Args:
        ip:           IP del host.
        port:         Puerto a sondear.
        service_hint: Nombre de servicio estimado (del KNOWN_SERVICES dict).
        timeout:      Tiempo máximo por operación de red.

    Returns:
        Tupla (service_name, service_version, banner).
        Todos los campos pueden ser cadena vacía si no se detecta nada.
    """
    service_name    = service_hint or KNOWN_SERVICES.get(port, "unknown")
    service_version = ""
    banner          = ""

    # Ajustar timeout para servicios lentos
    if service_name in SLOW_SERVICES:
        timeout = max(timeout, 3.0)

    probe = SERVICE_PROBES.get(service_name, SERVICE_PROBES["http"])

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # Leer banner automático que envían algunos servicios
            if not probe:
                sock.settimeout(1.5)
                try:
                    data = sock.recv(2048).decode("utf-8", errors="ignore").strip()
                    if data:
                        banner = data.split("\n")[0][:300].strip()
                except socket.timeout:
                    pass

            else:
                # Enviar sonda y leer respuesta
                sock.send(probe)
                sock.settimeout(1.5)
                try:
                    data = sock.recv(2048).decode("utf-8", errors="ignore").strip()
                    if data:
                        banner = data.split("\n")[0][:300].strip()
                except socket.timeout:
                    pass

            # Extraer versión del banner
            if banner:
                service_version = _extract_version(banner)

    except (ConnectionRefusedError, socket.timeout, BrokenPipeError):
        pass
    except OSError as e:
        logger.debug(f"probe_service OSError {ip}:{port} → {e}")
    except Exception as e:
        logger.debug(f"probe_service error {ip}:{port} → {e}")

    return service_name, service_version, banner


def _extract_version(banner: str) -> str:
    """
    Extrae el número de versión de un banner de servicio.

    Recorre los patrones definidos en VERSION_PATTERNS y devuelve
    el primer match encontrado, truncado a 100 caracteres.

    Args:
        banner: Primera línea del banner del servicio.

    Returns:
        Cadena de versión o cadena vacía si no se detecta.
    """
    for pattern, _ in VERSION_PATTERNS:
        match = pattern.search(banner)
        if match:
            try:
                version = match.group(1).strip()
                return version[:100]
            except IndexError:
                continue
    return ""


def build_cpe(service_name: str, version: str) -> str:
    """
    Construye un CPE (Common Platform Enumeration) básico.

    El CPE se usa para buscar CVEs en la NVD de forma más precisa.
    Formato: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*

    Args:
        service_name: Nombre del servicio (ej: "apache_httpd").
        version:      Versión detectada (ej: "2.4.49").

    Returns:
        String CPE o cadena vacía si no se puede construir.
    """
    if not service_name or not version or service_name == "unknown":
        return ""

    #: Mapeo servicio → (vendor, product)
    CPE_MAP: Dict[str, Tuple[str, str]] = {
        "apache_httpd":  ("apache",      "http_server"),
        "nginx":         ("nginx",       "nginx"),
        "iis":           ("microsoft",   "iis"),
        "openssh":       ("openbsd",     "openssh"),
        "ssh":           ("openssh",     "openssh"),
        "vsftpd":        ("beasts",      "vsftpd"),
        "proftpd":       ("proftpd",     "proftpd"),
        "mysql":         ("mysql",       "mysql"),
        "mariadb":       ("mariadb",     "mariadb"),
        "postgresql":    ("postgresql",  "postgresql"),
        "redis":         ("redis",       "redis"),
        "mongodb":       ("mongodb",     "mongodb"),
        "exim":          ("exim",        "exim"),
        "postfix":       ("postfix",     "postfix"),
    }

    if service_name in CPE_MAP:
        vendor, product = CPE_MAP[service_name]
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    return ""


# ══════════════════════════════════════════════════════════════
# OS FINGERPRINTING
# ══════════════════════════════════════════════════════════════

_TTL_OS_MAP: List[Tuple[int, int, str]] = [
    (1,   64,  "Linux / Unix / macOS"),
    (65,  128, "Windows"),
    (129, 255, "Dispositivo de red (Cisco / F5 / otros)"),
]

def fingerprint_os(ip: str, open_ports: List[PortResult]) -> Tuple[str, int]:
    """
    Intenta determinar el sistema operativo del host.

    Estrategia:
    1. Analizar banners de puertos abiertos (SSH, HTTP, SMB).
    2. Si no hay suficiente info, inferir por TTL del ping.

    Args:
        ip:          IP del host.
        open_ports:  Puertos abiertos con banners.

    Returns:
        Tupla (os_description, confidence_pct).
        confidence_pct: 0-100.
    """
    # ── Análisis de banners ────────────────────────────────────
    os_hints = _os_from_banners(open_ports)
    if os_hints:
        return os_hints

    # ── Fallback: TTL del ping ─────────────────────────────────
    return _os_from_ttl(ip)


def _os_from_banners(ports: List[PortResult]) -> Tuple[str, int]:
    """Extrae pistas de OS de los banners capturados."""

    os_patterns = [
        # Windows indicators
        (re.compile(r"Windows", re.I),            "Windows",         80),
        (re.compile(r"Microsoft", re.I),           "Windows",         70),
        (re.compile(r"Microsoft-IIS", re.I),       "Windows (IIS)",   90),
        (re.compile(r"DESKTOP-|WIN-", re.I),       "Windows",         85),
        # Linux indicators
        (re.compile(r"Ubuntu", re.I),              "Linux (Ubuntu)",  90),
        (re.compile(r"Debian", re.I),              "Linux (Debian)",  90),
        (re.compile(r"CentOS|Red Hat|RHEL", re.I),"Linux (RHEL)",    90),
        (re.compile(r"Kali",   re.I),              "Linux (Kali)",    90),
        (re.compile(r"OpenSSH.*Ubuntu", re.I),     "Linux (Ubuntu)",  85),
        (re.compile(r"OpenSSH.*Debian", re.I),     "Linux (Debian)",  85),
        # BSD
        (re.compile(r"FreeBSD|OpenBSD|NetBSD", re.I), "BSD",          90),
        # Cisco
        (re.compile(r"Cisco", re.I),               "Cisco IOS",       85),
    ]

    for port in ports:
        if not port.banner:
            continue
        for pattern, os_name, confidence in os_patterns:
            if pattern.search(port.banner):
                logger.debug(f"OS detectado por banner: {os_name} ({confidence}%)")
                return os_name, confidence

    return "", 0


def _os_from_ttl(ip: str) -> Tuple[str, int]:
    """Infiere el OS por el TTL de respuesta al ping."""
    sistema = platform.system().lower()
    cmd = (["ping", "-c", "1", ip] if sistema != "windows"
           else ["ping", "-n", "1", ip])

    try:
        output = subprocess.run(
            cmd, capture_output=True, text=True, timeout=4
        ).stdout

        ttl_match = re.search(r"ttl=(\d+)", output, re.I)
        if not ttl_match:
            return "", 0

        ttl = int(ttl_match.group(1))

        for lo, hi, os_name in _TTL_OS_MAP:
            if lo <= ttl <= hi:
                confidence = 50 if ttl not in (64, 128, 255) else 60
                logger.debug(f"OS inferido por TTL={ttl}: {os_name} ({confidence}%)")
                return os_name, confidence

    except Exception as e:
        logger.debug(f"_os_from_ttl {ip}: {e}")

    return "", 0


# ══════════════════════════════════════════════════════════════
# SONDEO COMPLETO DE UN HOST
# ══════════════════════════════════════════════════════════════

def probe_host(
    ip: str,
    open_ports: List[PortResult],
    timeout: float = 2.0,
) -> List[dict]:
    """
    Sondea todos los puertos abiertos de un host para obtener
    información de servicio, versión y CPE.

    Args:
        ip:         IP del host.
        open_ports: Lista de PortResult con state="open".
        timeout:    Timeout por sondeo en segundos.

    Returns:
        Lista de dicts con información enriquecida por puerto:
        [
          {
            "number":          80,
            "protocol":        "tcp",
            "state":           "open",
            "service_name":    "http",
            "service_version": "Apache 2.4.49",
            "service_banner":  "HTTP/1.1 200 OK\nServer: Apache/2.4.49",
            "cpe":             "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
          },
          ...
        ]
    """
    results = []

    for port_result in open_ports:
        port_num = port_result.number
        hint     = KNOWN_SERVICES.get(port_num, "")

        logger.debug(f"Probing {ip}:{port_num} ({hint or 'unknown'})")

        svc_name, svc_version, banner = probe_service(
            ip, port_num, hint, timeout
        )

        # Si el port scanner ya capturó un banner mejor, usarlo
        existing_banner = port_result.banner
        final_banner    = banner if len(banner) >= len(existing_banner) else existing_banner

        cpe = build_cpe(svc_name, svc_version)

        results.append({
            "number":          port_num,
            "protocol":        "tcp",
            "state":           "open",
            "service_name":    svc_name,
            "service_version": svc_version,
            "service_banner":  final_banner[:500],
            "cpe":             cpe,
        })

    return results
