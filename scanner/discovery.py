"""
scanner/discovery.py — Descubrimiento de hosts activos mediante Ping Sweep.

Soporta:
    - IP individual:  192.168.1.41
    - Rango CIDR:     192.168.1.0/24
    - Hostname:       servidor.empresa.com

El descubrimiento usa ICMP (ping del sistema operativo) y es multiplataforma
(Linux, macOS, Windows). La ejecución es concurrente con ThreadPoolExecutor.
"""

import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional

from core.logger import get_logger

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════
# PARSEO DE OBJETIVOS
# ══════════════════════════════════════════════════════════════

def parse_target(target: str) -> List[str]:
    """
    Convierte un objetivo en una lista de IPs a analizar.

    Soporta:
        "192.168.1.41"      → ["192.168.1.41"]
        "192.168.1.0/24"    → ["192.168.1.1", ..., "192.168.1.254"]
        "192.168.1.10-20"   → ["192.168.1.10", ..., "192.168.1.20"]
        "servidor.local"    → ["192.168.1.X"] (resolución DNS)

    Args:
        target: IP, CIDR, rango con guión o hostname.

    Returns:
        Lista de strings con las IPs a escanear.

    Raises:
        ValueError: Si el formato no es reconocido.
    """
    target = target.strip()

    # ── CIDR (192.168.1.0/24) ────────────────────────────────
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
        if not hosts:
            # Red /32 — IP individual
            hosts = [target.split("/")[0]]
        logger.debug(f"Target {target} → {len(hosts)} IPs (CIDR)")
        return hosts
    except ValueError:
        pass

    # ── Rango con guión (192.168.1.10-20) ────────────────────
    if "-" in target:
        parts = target.rsplit("-", 1)
        if len(parts) == 2 and parts[1].isdigit():
            base = ".".join(parts[0].split(".")[:-1])
            start = int(parts[0].split(".")[-1])
            end   = int(parts[1])
            hosts = [f"{base}.{i}" for i in range(start, end + 1)]
            logger.debug(f"Target {target} → {len(hosts)} IPs (rango)")
            return hosts

    # ── Hostname o IP individual ──────────────────────────────
    try:
        ip = socket.gethostbyname(target)
        logger.debug(f"Target {target} → {ip} (resolución DNS)")
        return [ip]
    except socket.gaierror as e:
        raise ValueError(f"No se pudo resolver '{target}': {e}") from e


# ══════════════════════════════════════════════════════════════
# PING DE UN HOST
# ══════════════════════════════════════════════════════════════

def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """
    Comprueba si un host está activo enviando un ping ICMP.

    Usa el comando ping del sistema operativo para compatibilidad
    máxima sin necesidad de permisos de root (raw sockets).

    Args:
        ip:      Dirección IP a sondear.
        timeout: Tiempo máximo de espera en segundos.

    Returns:
        True si el host responde, False en caso contrario.
    """
    sistema = platform.system().lower()

    if sistema == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        # -W en Linux es segundos; limitar a mínimo 1
        wait = str(max(1, int(timeout)))
        cmd  = ["ping", "-c", "1", "-W", wait, ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        # Si ping no está disponible, intentar conexión TCP al 80
        return _tcp_probe(ip, port=80, timeout=timeout)
    except Exception as e:
        logger.debug(f"ping_host error {ip}: {e}")
        return False


def _tcp_probe(ip: str, port: int = 80, timeout: float = 1.0) -> bool:
    """Alternativa al ping usando conexión TCP. Útil en sistemas sin ICMP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════
# PING SWEEP CONCURRENTE
# ══════════════════════════════════════════════════════════════

def discover_hosts(
    target: str,
    timeout: float      = 1.0,
    max_workers: int    = 100,
    progress_cb: Optional[Callable[[int, int, str, bool], None]] = None,
) -> List[str]:
    """
    Realiza un Ping Sweep concurrente sobre el objetivo.

    Args:
        target:      IP, CIDR o hostname objetivo.
        timeout:     Timeout por host en segundos.
        max_workers: Hilos concurrentes máximos.
        progress_cb: Callback(completado, total, ip, alive) — progreso en tiempo real.

    Returns:
        Lista de IPs activas, ordenada numéricamente.

    Raises:
        ValueError: Si el target tiene formato inválido.
    """
    ips   = parse_target(target)
    total = len(ips)
    alive: List[str] = []

    workers = min(max_workers, total, 500)

    logger.info(
        f"Ping Sweep iniciado — objetivo: {target} "
        f"({total} host(s), {workers} hilos, timeout={timeout}s)"
    )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_ip = {
            executor.submit(ping_host, ip, timeout): ip
            for ip in ips
        }

        completed = 0
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            completed += 1

            try:
                is_alive = future.result()
            except Exception as exc:
                logger.debug(f"Error pinging {ip}: {exc}")
                is_alive = False

            if is_alive:
                alive.append(ip)
                logger.debug(f"Host activo: {ip}")

            if progress_cb:
                progress_cb(completed, total, ip, is_alive)

    # Ordenar numéricamente por octetos
    def _sort_key(ip: str) -> tuple:
        try:
            return tuple(int(o) for o in ip.split("."))
        except ValueError:
            return (0, 0, 0, 0)

    alive_sorted = sorted(alive, key=_sort_key)

    logger.info(
        f"Ping Sweep completado — {len(alive_sorted)}/{total} "
        f"host(s) activo(s) en {target}"
    )

    return alive_sorted
