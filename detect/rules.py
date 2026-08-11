"""
detect/rules.py — Catálogo de reglas de detección de seguridad.

Cada regla detecta un patrón de riesgo que no necesita tener un CVE
asociado pero representa una configuración peligrosa en producción:
servicios sin cifrar, protocolos obsoletos, interfaces administrativas
expuestas, software desactualizado, etc.

Estructura de una regla:
    rule_id:     Identificador único (RULE-NNN)
    name:        Nombre corto descriptivo
    severity:    Nivel de severidad (Severity enum)
    description: Explicación del riesgo en lenguaje natural
    remediation: Acción correctora recomendada
    tags:        Categorías para filtrado
    evaluate:    Función (ports: List[dict]) → List[str]
                 Devuelve lista de strings de evidencia.
                 Lista vacía = regla no disparada.
"""

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from core.models import Severity


# ══════════════════════════════════════════════════════════════
# DATACLASS RULE
# ══════════════════════════════════════════════════════════════

@dataclass
class Rule:
    """Definición de una regla de detección."""

    rule_id:     str
    name:        str
    severity:    Severity
    description: str
    remediation: str
    tags:        List[str]
    evaluate:    Callable[[List[dict]], List[str]]

    def check(self, ports: List[dict]) -> List[str]:
        """
        Evalúa la regla contra los puertos de un host.

        Args:
            ports: Lista de dicts con info de puertos abiertos.
                   Cada dict tiene: number, service_name, service_version,
                   service_banner, is_dangerous.

        Returns:
            Lista de strings de evidencia. Vacía si la regla no aplica.
        """
        try:
            return self.evaluate(ports) or []
        except Exception:
            return []


# ══════════════════════════════════════════════════════════════
# FUNCIONES AUXILIARES DE EVALUACIÓN
# ══════════════════════════════════════════════════════════════

def _port_open(ports: List[dict], number: int) -> Optional[dict]:
    """Devuelve el dict del puerto si está abierto, None en caso contrario."""
    return next((p for p in ports if p["number"] == number), None)

def _port_numbers(ports: List[dict]) -> List[int]:
    """Lista de números de puerto abiertos."""
    return [p["number"] for p in ports]

def _version_tuple(version_str: str) -> tuple:
    """Convierte '2.4.49' a (2, 4, 49) para comparaciones."""
    try:
        nums = re.findall(r"\d+", version_str)
        return tuple(int(n) for n in nums[:4])
    except Exception:
        return (0,)

def _extract_version(service_version: str) -> str:
    """Extrae solo el número de versión de un string como 'Apache/2.4.49'."""
    match = re.search(r"[\d]+\.[\d]+\.?[\d]*", service_version)
    return match.group() if match else ""


# ══════════════════════════════════════════════════════════════
# CATÁLOGO DE REGLAS
# ══════════════════════════════════════════════════════════════

RULES: List[Rule] = [

    # ── RULE-001: Telnet ───────────────────────────────────────
    Rule(
        rule_id     = "RULE-001",
        name        = "Telnet expuesto",
        severity    = Severity.HIGH,
        description = (
            "El servicio Telnet (TCP/23) está activo. Telnet transmite "
            "todos los datos, incluyendo credenciales de autenticación, "
            "en texto plano. Cualquier atacante en la ruta de red puede "
            "capturar sesiones completas con herramientas básicas como tcpdump."
        ),
        remediation = (
            "Deshabilitar Telnet y migrar a SSH (OpenSSH). En Linux: "
            "'sudo systemctl disable telnet.socket --now'. "
            "Configurar autenticación por clave pública en SSH."
        ),
        tags        = ["cleartext", "remote-access", "network"],
        evaluate    = lambda ports: (
            [f"Puerto 23/TCP abierto con servicio: {_port_open(ports, 23).get('service_name', 'telnet')}"]
            if _port_open(ports, 23) else []
        ),
    ),

    # ── RULE-002: FTP sin cifrar ───────────────────────────────
    Rule(
        rule_id     = "RULE-002",
        name        = "FTP sin cifrar expuesto",
        severity    = Severity.MEDIUM,
        description = (
            "El servicio FTP (TCP/21) está activo. FTP transmite credenciales "
            "y archivos en texto plano. Es vulnerable a ataques de sniffing, "
            "credential theft y bounce attacks. También es vector frecuente "
            "de acceso anónimo si no está correctamente configurado."
        ),
        remediation = (
            "Sustituir FTP por SFTP (SSH File Transfer Protocol) o FTPS. "
            "Si FTP es necesario: deshabilitar acceso anónimo, usar FTPS "
            "con certificado válido y restringir por IP mediante firewall."
        ),
        tags        = ["cleartext", "file-transfer", "network"],
        evaluate    = lambda ports: (
            [f"Puerto 21/TCP abierto. Banner: {_port_open(ports, 21).get('service_banner', '')[:80]}"]
            if _port_open(ports, 21) else []
        ),
    ),

    # ── RULE-003: NetBIOS / SMBv1 ─────────────────────────────
    Rule(
        rule_id     = "RULE-003",
        name        = "NetBIOS-SSN expuesto (posible SMBv1)",
        severity    = Severity.HIGH,
        description = (
            "El puerto 139/TCP (NetBIOS Session Service) está abierto, "
            "indicando soporte de SMBv1. SMBv1 es el protocolo explotado por "
            "EternalBlue (MS17-010), usado en WannaCry y NotPetya. "
            "Microsoft recomienda desactivarlo desde 2017."
        ),
        remediation = (
            "Deshabilitar SMBv1: "
            "PowerShell: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'. "
            "Bloquear puertos 137-139 en el firewall perimetral."
        ),
        tags        = ["smb", "legacy-protocol", "network", "eternalblue"],
        evaluate    = lambda ports: (
            ["Puerto 139/TCP abierto — NetBIOS Session Service activo (indicador de SMBv1)"]
            if _port_open(ports, 139) else []
        ),
    ),

    # ── RULE-004: SMB expuesto ────────────────────────────────
    Rule(
        rule_id     = "RULE-004",
        name        = "SMB (445) expuesto en la red",
        severity    = Severity.HIGH,
        description = (
            "El puerto 445/TCP (SMB directo sobre TCP) está abierto. "
            "SMB es un protocolo crítico pero altamente explotado: "
            "EternalBlue, PrintNightmare, PetitPotam y ataques de relay NTLM "
            "utilizan este puerto como vector de entrada."
        ),
        remediation = (
            "Bloquear el puerto 445 en el firewall de entrada salvo que sea "
            "estrictamente necesario. Deshabilitar SMBv1, activar SMB signing "
            "y asegurar que el sistema tiene los parches MS17-010 aplicados."
        ),
        tags        = ["smb", "network", "lateral-movement"],
        evaluate    = lambda ports: (
            [f"Puerto 445/TCP abierto. Banner: {_port_open(ports, 445).get('service_banner', '')[:80]}"]
            if _port_open(ports, 445) else []
        ),
    ),

    # ── RULE-005: RDP expuesto ────────────────────────────────
    Rule(
        rule_id     = "RULE-005",
        name        = "RDP expuesto directamente en la red",
        severity    = Severity.HIGH,
        description = (
            "El Escritorio Remoto de Windows (TCP/3389) está expuesto. "
            "RDP es uno de los vectores de entrada más explotados: ataques "
            "de fuerza bruta, BlueKeep (CVE-2019-0708), credential stuffing "
            "y campañas de ransomware lo utilizan masivamente."
        ),
        remediation = (
            "No exponer RDP directamente a internet. Usar VPN como paso previo "
            "o acceso a través de un bastión (jump host). "
            "Habilitar NLA (Network Level Authentication), cambiar el puerto "
            "por defecto y limitar acceso por IP en el firewall."
        ),
        tags        = ["rdp", "remote-access", "brute-force"],
        evaluate    = lambda ports: (
            ["Puerto 3389/TCP (RDP) abierto y accesible directamente"]
            if _port_open(ports, 3389) else []
        ),
    ),

    # ── RULE-006: Redis sin autenticación ─────────────────────
    Rule(
        rule_id     = "RULE-006",
        name        = "Redis posiblemente sin autenticación",
        severity    = Severity.CRITICAL,
        description = (
            "El puerto 6379/TCP (Redis) está abierto y el banner indica "
            "que el servidor responde sin autenticación previa. "
            "Redis sin contraseña permite leer/escribir toda la memoria "
            "del servidor, configurar cron jobs y potencialmente ejecutar "
            "código arbitrario mediante escritura de archivos."
        ),
        remediation = (
            "Configurar 'requirepass <contraseña-fuerte>' en redis.conf. "
            "Bind Redis solo a localhost (127.0.0.1) si no se necesita acceso remoto. "
            "Desactivar comandos peligrosos con 'rename-command'. "
            "Nunca exponer Redis a internet directamente."
        ),
        tags        = ["database", "no-auth", "rce"],
        evaluate    = lambda ports: (
            [f"Puerto 6379/TCP abierto. Banner: {_port_open(ports, 6379).get('service_banner', '')[:100]}"]
            if _port_open(ports, 6379) and
               (not _port_open(ports, 6379).get("service_banner") or
                "+PONG" in (_port_open(ports, 6379).get("service_banner") or ""))
            else []
        ),
    ),

    # ── RULE-007: MongoDB sin autenticación ───────────────────
    Rule(
        rule_id     = "RULE-007",
        name        = "MongoDB posiblemente sin autenticación",
        severity    = Severity.CRITICAL,
        description = (
            "El puerto 27017/TCP (MongoDB) está expuesto. MongoDB en versiones "
            "antiguas no tenía autenticación habilitada por defecto, "
            "lo que causó filtraciones masivas de datos en internet. "
            "Cualquier acceso no autenticado permite leer, modificar o borrar "
            "todas las bases de datos."
        ),
        remediation = (
            "Habilitar autenticación en MongoDB: 'security.authorization: enabled' "
            "en mongod.conf. Bind solo a localhost o IPs específicas. "
            "Nunca exponer el puerto 27017 directamente a internet."
        ),
        tags        = ["database", "no-auth", "data-exposure"],
        evaluate    = lambda ports: (
            ["Puerto 27017/TCP (MongoDB) expuesto directamente en la red"]
            if _port_open(ports, 27017) else []
        ),
    ),

    # ── RULE-008: Elasticsearch sin autenticación ─────────────
    Rule(
        rule_id     = "RULE-008",
        name        = "Elasticsearch posiblemente sin autenticación",
        severity    = Severity.CRITICAL,
        description = (
            "El puerto 9200/TCP (Elasticsearch) está expuesto. "
            "Elasticsearch sin autenticación permite acceso completo a todos "
            "los índices y datos almacenados. Ha sido vector de miles de "
            "brechas de datos al estar expuesto a internet sin protección."
        ),
        remediation = (
            "Habilitar la funcionalidad de seguridad (Elastic Security): "
            "'xpack.security.enabled: true' en elasticsearch.yml. "
            "Implementar TLS y crear usuarios con contraseñas fuertes. "
            "Restringir acceso con firewall a las IPs necesarias."
        ),
        tags        = ["database", "no-auth", "data-exposure"],
        evaluate    = lambda ports: (
            ["Puerto 9200/TCP (Elasticsearch) expuesto — posible acceso sin autenticación"]
            if _port_open(ports, 9200) else []
        ),
    ),

    # ── RULE-009: Docker API sin TLS ──────────────────────────
    Rule(
        rule_id     = "RULE-009",
        name        = "Docker API sin TLS expuesta",
        severity    = Severity.CRITICAL,
        description = (
            "El puerto 2375/TCP (Docker API sin TLS) está abierto. "
            "Acceder a la API de Docker sin autenticación da control total "
            "sobre todos los contenedores. Un atacante puede lanzar "
            "contenedores privilegiados para escapar al host y obtener "
            "acceso root al sistema operativo subyacente."
        ),
        remediation = (
            "Nunca exponer el socket de Docker sin TLS. "
            "Configurar Docker con TLS: '--tlsverify --tlscacert --tlscert --tlskey'. "
            "Usar el socket Unix local (/var/run/docker.sock) cuando sea posible. "
            "Si se necesita acceso remoto, usar SSH tunneling."
        ),
        tags        = ["container", "docker", "rce", "privilege-escalation"],
        evaluate    = lambda ports: (
            ["Puerto 2375/TCP (Docker API sin TLS) expuesto — acceso root posible"]
            if _port_open(ports, 2375) else []
        ),
    ),

    # ── RULE-010: VNC expuesto ────────────────────────────────
    Rule(
        rule_id     = "RULE-010",
        name        = "VNC expuesto en la red",
        severity    = Severity.HIGH,
        description = (
            "El puerto 5900/TCP (VNC) está abierto. VNC es un protocolo "
            "de acceso remoto gráfico frecuentemente configurado sin "
            "autenticación o con contraseñas débiles de 8 caracteres. "
            "Da acceso visual completo al escritorio del sistema."
        ),
        remediation = (
            "No exponer VNC directamente. Usar VPN o SSH tunnel: "
            "'ssh -L 5900:localhost:5900 usuario@servidor'. "
            "Configurar autenticación fuerte y cifrado TLS en VNC. "
            "Considerar alternativas más seguras (RDP con NLA, X2Go)."
        ),
        tags        = ["remote-access", "desktop", "brute-force"],
        evaluate    = lambda ports: (
            [f"Puerto 5900/TCP (VNC) expuesto. Banner: {_port_open(ports, 5900).get('service_banner', '')[:60]}"]
            if _port_open(ports, 5900) else []
        ),
    ),

    # ── RULE-011: SNMP expuesto ───────────────────────────────
    Rule(
        rule_id     = "RULE-011",
        name        = "SNMP expuesto (community string public)",
        severity    = Severity.MEDIUM,
        description = (
            "El puerto 161/UDP (SNMP) está activo. SNMP v1/v2c usa "
            "'community strings' como contraseña, siendo 'public' y 'private' "
            "los valores por defecto. Un atacante puede extraer información "
            "detallada del sistema: interfaces, rutas, procesos y configuración."
        ),
        remediation = (
            "Si SNMP es necesario, migrar a SNMPv3 con autenticación y cifrado. "
            "Cambiar las community strings por defecto. "
            "Restringir acceso SNMP solo a IPs del sistema de monitorización. "
            "Si no se usa, deshabilitar el servicio."
        ),
        tags        = ["snmp", "information-disclosure", "network"],
        evaluate    = lambda ports: (
            ["Puerto 161/UDP (SNMP) activo — posible community string 'public' por defecto"]
            if _port_open(ports, 161) else []
        ),
    ),

    # ── RULE-012: LDAP sin TLS ────────────────────────────────
    Rule(
        rule_id     = "RULE-012",
        name        = "LDAP sin cifrar expuesto",
        severity    = Severity.MEDIUM,
        description = (
            "El puerto 389/TCP (LDAP) está abierto sin TLS. "
            "LDAP en texto plano expone credenciales de Active Directory "
            "o directorios LDAP a ataques de sniffing. "
            "Combinado con un ataque MitM puede capturar hashes y contraseñas."
        ),
        remediation = (
            "Forzar LDAPS (puerto 636) con certificado TLS válido. "
            "Habilitar 'LDAP channel binding' y 'LDAP signing' en Active Directory. "
            "Bloquear el puerto 389 en el firewall y usar solo 636."
        ),
        tags        = ["ldap", "active-directory", "cleartext"],
        evaluate    = lambda ports: (
            ["Puerto 389/TCP (LDAP sin TLS) expuesto — credenciales en texto plano"]
            if _port_open(ports, 389) and not _port_open(ports, 636) else []
        ),
    ),

    # ── RULE-013: Bases de datos expuestas directamente ───────
    Rule(
        rule_id     = "RULE-013",
        name        = "Base de datos expuesta directamente en la red",
        severity    = Severity.HIGH,
        description = (
            "Hay uno o más servicios de base de datos (MySQL/MariaDB, "
            "PostgreSQL, MSSQL u Oracle) expuestos directamente en la red "
            "sin pasar por una capa de aplicación. Las BD nunca deberían "
            "ser accesibles directamente desde internet o redes no confiables."
        ),
        remediation = (
            "Colocar las bases de datos en una red privada (VLAN o subnet). "
            "Acceder solo desde la capa de aplicación (backend). "
            "Si se necesita administración remota, usar SSH tunnel. "
            "Implementar autenticación fuerte y cifrar las conexiones."
        ),
        tags        = ["database", "network-exposure"],
        evaluate    = lambda ports: (
            [
                f"Base de datos expuesta: "
                + ", ".join(
                    f"puerto {p['number']}/TCP ({p.get('service_name','?')})"
                    for p in ports if p["number"] in {3306, 5432, 1433, 1521}
                )
            ]
            if any(p["number"] in {3306, 5432, 1433, 1521} for p in ports)
            else []
        ),
    ),

    # ── RULE-014: SSH versión obsoleta ────────────────────────
    Rule(
        rule_id     = "RULE-014",
        name        = "OpenSSH versión potencialmente obsoleta",
        severity    = Severity.MEDIUM,
        description = (
            "La versión de OpenSSH detectada es anterior a 8.0. "
            "Versiones antiguas pueden ser vulnerables a timing attacks "
            "en la enumeración de usuarios (CVE-2018-15473), "
            "y otras vulnerabilidades parcheadas en versiones recientes."
        ),
        remediation = (
            "Actualizar OpenSSH a la versión más reciente disponible. "
            "En Debian/Ubuntu: 'apt upgrade openssh-server'. "
            "Deshabilitar algoritmos de cifrado obsoletos en sshd_config. "
            "Usar autenticación por clave pública y deshabilitar contraseñas."
        ),
        tags        = ["ssh", "version", "outdated"],
        evaluate    = lambda ports: (
            _check_ssh_version(ports)
        ),
    ),

    # ── RULE-015: Apache versión conocida vulnerable ───────────
    Rule(
        rule_id     = "RULE-015",
        name        = "Apache HTTP Server versión con vulnerabilidades conocidas",
        severity    = Severity.HIGH,
        description = (
            "Se detectó Apache HTTP Server en una versión con vulnerabilidades "
            "críticas conocidas (ej: 2.4.49 tiene Path Traversal+RCE CVE-2021-41773, "
            "2.4.50 tiene el bypass del mismo). Estas versiones son explotadas "
            "activamente en el mundo real."
        ),
        remediation = (
            "Actualizar Apache a la versión más reciente de la rama 2.4.x. "
            "En Ubuntu/Debian: 'apt upgrade apache2'. "
            "Verificar la versión con: 'apache2 -v'. "
            "Revisar el changelog de seguridad: https://httpd.apache.org/security/"
        ),
        tags        = ["apache", "version", "rce", "path-traversal"],
        evaluate    = lambda ports: (
            _check_apache_version(ports)
        ),
    ),

    # ── RULE-016: HTTP sin HTTPS ──────────────────────────────
    Rule(
        rule_id     = "RULE-016",
        name        = "HTTP disponible sin HTTPS",
        severity    = Severity.LOW,
        description = (
            "El servidor web responde en HTTP (puerto 80) pero no tiene "
            "HTTPS (puerto 443) habilitado, o tiene ambos pero sin "
            "redirección automática de HTTP a HTTPS. "
            "El tráfico HTTP es susceptible a ataques MitM y manipulación."
        ),
        remediation = (
            "Habilitar HTTPS con un certificado TLS válido (Let's Encrypt es gratuito). "
            "Configurar redirección permanente de HTTP a HTTPS (301). "
            "Implementar HSTS: 'Strict-Transport-Security: max-age=31536000'. "
            "Eliminar el puerto 80 del firewall si ya no es necesario."
        ),
        tags        = ["http", "tls", "cleartext"],
        evaluate    = lambda ports: (
            ["Puerto 80/HTTP abierto pero no se detectó puerto 443/HTTPS"]
            if _port_open(ports, 80) and not _port_open(ports, 443) else []
        ),
    ),

    # ── RULE-017: Múltiples servicios peligrosos ──────────────
    Rule(
        rule_id     = "RULE-017",
        name        = "Alto número de puertos peligrosos expuestos",
        severity    = Severity.HIGH,
        description = (
            "El host expone 3 o más puertos clasificados como peligrosos. "
            "Esto indica una posible ausencia de segmentación de red y "
            "principio de mínimo privilegio. Cada puerto peligroso expuesto "
            "incrementa la superficie de ataque del sistema."
        ),
        remediation = (
            "Revisar qué servicios son realmente necesarios y deshabilitar "
            "o restringir mediante firewall los que no lo sean. "
            "Aplicar el principio de mínima exposición: solo exponer "
            "los servicios estrictamente necesarios para su función."
        ),
        tags        = ["attack-surface", "hardening", "network"],
        evaluate    = lambda ports: (
            _check_dangerous_port_count(ports)
        ),
    ),

    # ── RULE-018: SNMP v1/v2 ──────────────────────────────────
    Rule(
        rule_id     = "RULE-018",
        name        = "Panel administrativo HTTP en puerto no estándar",
        severity    = Severity.MEDIUM,
        description = (
            "Se detectó un servicio HTTP en un puerto alternativo (8080, 8443, "
            "8888, 9090, 4848, etc.) que podría ser un panel de administración "
            "web. Estos paneles frecuentemente tienen credenciales por defecto "
            "o interfaces expuestas sin autenticación robusta."
        ),
        remediation = (
            "Identificar qué aplicación está corriendo en el puerto. "
            "Cambiar las credenciales por defecto del panel. "
            "Proteger el acceso con autenticación fuerte o MFA. "
            "Restringir el acceso mediante firewall a IPs de administración."
        ),
        tags        = ["admin-panel", "http", "default-credentials"],
        evaluate    = lambda ports: (
            [
                f"Panel HTTP en puerto no estándar: "
                + ", ".join(
                    f"{p['number']}/TCP"
                    for p in ports
                    if p["number"] in {8080, 8443, 8888, 9090, 4848, 9200, 4200, 9000}
                )
            ]
            if any(p["number"] in {8080, 8443, 8888, 9090, 4848, 9200, 4200, 9000}
                   for p in ports)
            else []
        ),
    ),
]


# ══════════════════════════════════════════════════════════════
# FUNCIONES DE EVALUACIÓN COMPLEJAS (usadas por las reglas)
# ══════════════════════════════════════════════════════════════

def _check_ssh_version(ports: List[dict]) -> List[str]:
    """Verifica si la versión de SSH es potencialmente obsoleta."""
    ssh_port = _port_open(ports, 22)
    if not ssh_port:
        return []

    version_str = ssh_port.get("service_version", "") or ssh_port.get("service_banner", "")
    if not version_str:
        return []

    # Extraer versión de OpenSSH del banner (ej: SSH-2.0-OpenSSH_7.4)
    match = re.search(r"OpenSSH[_\s]([\d.p]+)", version_str, re.I)
    if not match:
        return []

    version = match.group(1).replace("p", ".")
    vtuple  = _version_tuple(version)

    if vtuple and vtuple < (8, 0):
        return [
            f"OpenSSH versión {match.group(1)} detectada "
            f"(< 8.0, recomendado actualizar). "
            f"Banner: {version_str[:100]}"
        ]
    return []


def _check_apache_version(ports: List[dict]) -> List[str]:
    """Verifica si la versión de Apache es conocida como vulnerable."""
    # Versiones Apache con vulnerabilidades críticas conocidas
    VULNERABLE_VERSIONS = {
        (2, 4, 49): "CVE-2021-41773 (Path Traversal + RCE)",
        (2, 4, 50): "CVE-2021-42013 (bypass de CVE-2021-41773)",
        (2, 4, 7):  "CVE-2014-0098 (DoS)",
    }

    for port in ports:
        if port.get("number") not in {80, 443, 8080, 8443}:
            continue

        banner  = port.get("service_banner", "") or ""
        version = port.get("service_version", "") or ""
        text    = banner + " " + version

        match = re.search(r"Apache/([\d.]+)", text, re.I)
        if not match:
            continue

        vtuple = _version_tuple(match.group(1))
        for vuln_ver, cve_info in VULNERABLE_VERSIONS.items():
            if vtuple == vuln_ver:
                return [
                    f"Apache {match.group(1)} en puerto {port['number']}/TCP — "
                    f"versión vulnerable: {cve_info}"
                ]

    return []


def _check_dangerous_port_count(ports: List[dict]) -> List[str]:
    """Verifica si hay demasiados puertos peligrosos expuestos."""
    DANGEROUS_PORTS = {
        21, 23, 135, 137, 138, 139, 445, 1433, 1521,
        2375, 2376, 3389, 5900, 6379, 9200, 27017,
    }
    dangerous = [p for p in ports if p["number"] in DANGEROUS_PORTS]

    if len(dangerous) >= 3:
        port_list = ", ".join(f"{p['number']}" for p in dangerous[:10])
        return [
            f"{len(dangerous)} puertos peligrosos expuestos: {port_list}"
        ]
    return []


# ══════════════════════════════════════════════════════════════
# REGISTRO DE REGLAS
# ══════════════════════════════════════════════════════════════

RULES_BY_ID: Dict[str, Rule] = {r.rule_id: r for r in RULES}


def get_rule(rule_id: str) -> Optional[Rule]:
    """Devuelve una regla por su ID, o None si no existe."""
    return RULES_BY_ID.get(rule_id)


def get_rules_by_tag(tag: str) -> List[Rule]:
    """Devuelve las reglas que contienen el tag indicado."""
    return [r for r in RULES if tag in r.tags]
