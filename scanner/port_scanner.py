"""
scanner/port_scanner.py — Escaneo de puertos TCP con threading.

Implementa un TCP Connect Scan: intenta establecer una conexión
completa en cada puerto. No requiere privilegios de root y es
compatible con cualquier sistema operativo.

Para cada puerto abierto se intenta capturar el banner del servicio
enviando una solicitud HTTP básica como sonda universal.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from core.logger import get_logger

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════

#: Servicios conocidos por número de puerto
KNOWN_SERVICES: Dict[int, str] = {
    20: "ftp-data",    21: "ftp",          22: "ssh",
    23: "telnet",      25: "smtp",          53: "dns",
    67: "dhcp",        68: "dhcp-client",   69: "tftp",
    80: "http",        110: "pop3",         111: "rpc",
    123: "ntp",        135: "msrpc",        137: "netbios-ns",
    138: "netbios-dgm",139: "netbios-ssn",  143: "imap",
    161: "snmp",       162: "snmptrap",     389: "ldap",
    443: "https",      445: "smb",          465: "smtps",
    514: "syslog",     587: "submission",   636: "ldaps",
    993: "imaps",      995: "pop3s",        1433: "mssql",
    1521: "oracle-db", 1723: "pptp",        2049: "nfs",
    2375: "docker",    2376: "docker-tls",  3306: "mysql",
    3389: "rdp",       5432: "postgresql",  5672: "amqp",
    5900: "vnc",       6379: "redis",       6443: "k8s-api",
    8080: "http-proxy",8443: "https-alt",   8888: "http-alt",
    9200: "elasticsearch", 9300: "elasticsearch-cluster",
    27017: "mongodb",  27018: "mongodb-http",
}

#: Rango de puertos más comunes para auditorías rápidas
COMMON_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,"
    "465,587,636,993,995,1433,1521,2049,2375,3306,3389,"
    "5432,5672,5900,6379,8080,8443,8888,9200,27017"
)


# ══════════════════════════════════════════════════════════════
# DATACLASS RESULTADO
# ══════════════════════════════════════════════════════════════

@dataclass
class PortResult:
    """Resultado del escaneo de un puerto individual."""
    number:   int
    protocol: str  = "tcp"
    state:    str  = "closed"   # open | closed | filtered
    banner:   str  = ""

    @property
    def service_name(self) -> str:
        """Nombre de servicio asociado al puerto."""
        return KNOWN_SERVICES.get(self.number, "unknown")

    def to_dict(self) -> dict:
        return {
            "number":       self.number,
            "protocol":     self.protocol,
            "state":        self.state,
            "banner":       self.banner,
            "service_name": self.service_name,
        }


# ══════════════════════════════════════════════════════════════
# PARSEO DE RANGO DE PUERTOS
# ══════════════════════════════════════════════════════════════

def parse_port_range(port_range: str) -> List[int]:
    """
    Convierte una especificación de puertos en una lista de enteros.

    Formatos soportados:
        "80"            → [80]
        "22,80,443"     → [22, 80, 443]
        "1-1024"        → [1, 2, ..., 1024]
        "22,80,8000-90" → [22, 80, 8000, 8001, ..., 8090]
        "common"        → Puertos más habituales en auditorías
        "all"           → 1-65535

    Args:
        port_range: Especificación de puertos.

    Returns:
        Lista de enteros únicos, ordenada ascendentemente.

    Raises:
        ValueError: Si algún valor está fuera del rango 1-65535.
    """
    pr = port_range.strip().lower()

    if pr == "all":
        return list(range(1, 65536))

    if pr == "common":
        return parse_port_range(COMMON_PORTS)

    ports: List[int] = []

    for segment in pr.split(","):
        segment = segment.strip()
        if not segment:
            continue

        if "-" in segment:
            parts = segment.split("-", 1)
            try:
                start = int(parts[0].strip())
                end   = int(parts[1].strip())
            except ValueError as exc:
                raise ValueError(f"Rango de puertos inválido: '{segment}'") from exc

            if not (1 <= start <= end <= 65535):
                raise ValueError(
                    f"Rango {start}-{end} fuera del límite (1-65535)"
                )
            ports.extend(range(start, end + 1))

        else:
            try:
                p = int(segment)
            except ValueError as exc:
                raise ValueError(f"Puerto inválido: '{segment}'") from exc

            if not (1 <= p <= 65535):
                raise ValueError(f"Puerto {p} fuera del rango (1-65535)")

            ports.append(p)

    return sorted(set(ports))


# ══════════════════════════════════════════════════════════════
# ESCANEO DE UN PUERTO
# ══════════════════════════════════════════════════════════════

def scan_port(ip: str, port: int, timeout: float = 1.0) -> PortResult:
    """
    Intenta una conexión TCP al puerto e intenta capturar el banner.

    El método es TCP Connect Scan:
    - Si connect_ex devuelve 0 → el puerto está abierto.
    - Luego se envía una sonda HTTP básica para provocar una respuesta
      (funciona también con FTP, SSH, SMTP que envían greeting propio).

    Args:
        ip:      IP del host objetivo.
        port:    Número de puerto (1-65535).
        timeout: Timeout de conexión y lectura en segundos.

    Returns:
        PortResult con el estado y el banner capturado (si aplica).
    """
    result = PortResult(number=port)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            ret = sock.connect_ex((ip, port))
            if ret != 0:
                result.state = "closed"
                return result

            result.state = "open"

            # Intentar capturar banner del servicio
            try:
                # Sonda HTTP como disparador universal
                sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: Ciber-Shield\r\n\r\n")
                data = sock.recv(2048).decode("utf-8", errors="ignore").strip()
                if data:
                    # Tomar solo la primera línea, truncar a 200 chars
                    result.banner = data.split("\n")[0][:200].strip()
            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                # Normal: muchos servicios no responden a la sonda HTTP
                pass
            except Exception as e:
                logger.debug(f"Banner error {ip}:{port} → {e}")

    except socket.timeout:
        result.state = "filtered"
    except ConnectionRefusedError:
        result.state = "closed"
    except OSError as e:
        # EHOSTUNREACH, ENETUNREACH, etc.
        logger.debug(f"OSError {ip}:{port} → {e}")
        result.state = "filtered"
    except Exception as e:
        logger.debug(f"Unexpected error {ip}:{port} → {e}")
        result.state = "filtered"

    return result


# ══════════════════════════════════════════════════════════════
# ESCANEO CONCURRENTE DE PUERTOS
# ══════════════════════════════════════════════════════════════

def scan_ports(
    ip: str,
    port_range: str    = "1-1024",
    timeout: float     = 1.0,
    max_workers: int   = 150,
    progress_cb: Optional[Callable[[int, int, Optional[PortResult]], None]] = None,
) -> List[PortResult]:
    """
    Escanea un rango de puertos TCP en un host de forma concurrente.

    Sólo devuelve los puertos con estado "open".

    Args:
        ip:          IP del host objetivo.
        port_range:  Especificación de puertos (ver parse_port_range).
        timeout:     Timeout por puerto en segundos.
        max_workers: Hilos concurrentes máximos.
        progress_cb: Callback(completado, total, resultado) — progreso.

    Returns:
        Lista de PortResult con state="open", ordenada por número de puerto.
    """
    ports = parse_port_range(port_range)
    total = len(ports)

    if total == 0:
        logger.warning(f"scan_ports: rango '{port_range}' vacío para {ip}")
        return []

    workers = min(max_workers, total, 500)
    open_ports: List[PortResult] = []

    logger.info(
        f"Port scan iniciado — host: {ip}, puertos: {total}, "
        f"hilos: {workers}, timeout: {timeout}s"
    )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, p, timeout): p
            for p in ports
        }

        completed = 0
        for future in as_completed(future_to_port):
            completed += 1

            try:
                result = future.result()
            except Exception as exc:
                port = future_to_port[future]
                logger.debug(f"Error escaneando {ip}:{port} → {exc}")
                result = PortResult(number=port, state="filtered")

            if result.state == "open":
                open_ports.append(result)
                logger.debug(
                    f"Puerto abierto: {ip}:{result.number}/tcp "
                    f"({result.service_name}) "
                    f"{'[banner]' if result.banner else ''}"
                )

            if progress_cb:
                progress_cb(
                    completed,
                    total,
                    result if result.state == "open" else None,
                )

    open_sorted = sorted(open_ports, key=lambda r: r.number)

    logger.info(
        f"Port scan completado — {ip}: "
        f"{len(open_sorted)} puerto(s) abierto(s) de {total} analizados"
    )

    return open_sorted
