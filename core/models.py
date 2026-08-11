"""
core/models.py — Modelos de base de datos con SQLAlchemy ORM.

Define todas las entidades del dominio:
    Scan          → Una auditoría de seguridad completa
    Host          → Un host descubierto dentro de una auditoría
    Port          → Un puerto abierto en un host
    Vulnerability → Un CVE correlacionado con un servicio
    Finding       → Un hallazgo del motor de reglas de detección
    Report        → Un informe generado a partir de una auditoría
"""

import json
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, Float,
    ForeignKey, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship


# ══════════════════════════════════════════════════════════════
# BASE Y ENUMS
# ══════════════════════════════════════════════════════════════

class Base(DeclarativeBase):
    """Base declarativa compartida por todos los modelos."""
    pass


class ScanStatus(str, PyEnum):
    """Estado del ciclo de vida de una auditoría."""
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"


class Severity(str, PyEnum):
    """Nivel de severidad para vulnerabilidades y hallazgos."""
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"
    NONE     = "none"

    @classmethod
    def from_cvss(cls, score: Optional[float]) -> "Severity":
        """Convierte una puntuación CVSS 3.x a nivel de severidad."""
        if score is None:
            return cls.NONE
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.NONE

    @property
    def color(self) -> str:
        """Color Bootstrap asociado a la severidad para el dashboard."""
        return {
            "critical": "danger",
            "high":     "warning",
            "medium":   "info",
            "low":      "secondary",
            "info":     "light",
            "none":     "light",
        }[self.value]

    @property
    def badge(self) -> str:
        """HTML badge Bootstrap para usar en templates."""
        return f'<span class="badge bg-{self.color}">{self.value.upper()}</span>'


# ══════════════════════════════════════════════════════════════
# MODELO: SCAN
# ══════════════════════════════════════════════════════════════

class Scan(Base):
    """
    Representa una auditoría de seguridad completa.

    Una auditoría agrupa todos los hosts descubiertos en un
    objetivo (IP individual o rango CIDR) y guarda el estado
    del proceso, las métricas agregadas y el riesgo global.
    """
    __tablename__ = "scans"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    name         = Column(String(200), nullable=False)
    target       = Column(String(255), nullable=False,
                          doc="IP, hostname o rango CIDR del objetivo")
    port_range   = Column(String(100), default="1-1024")
    status       = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    notes        = Column(Text)

    # ── Métricas agregadas (actualizadas al finalizar el escaneo) ──
    risk_score   = Column(Float,   default=0.0,
                          doc="Puntuación de riesgo global 0-10 basada en CVSS")
    total_hosts  = Column(Integer, default=0)
    total_open_ports = Column(Integer, default=0)
    total_vulns  = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)

    # ── Timestamps ────────────────────────────────────────────────
    created_at   = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    started_at   = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # ── Relaciones ────────────────────────────────────────────────
    hosts   = relationship("Host",   back_populates="scan",
                           cascade="all, delete-orphan", lazy="dynamic")
    reports = relationship("Report", back_populates="scan",
                           cascade="all, delete-orphan")

    # ── Propiedades calculadas ────────────────────────────────────
    @property
    def duration_seconds(self) -> Optional[float]:
        """Duración del escaneo en segundos."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def severity(self) -> Severity:
        """Severidad global derivada del risk_score."""
        return Severity.from_cvss(self.risk_score)

    @property
    def is_running(self) -> bool:
        return self.status == ScanStatus.RUNNING

    @property
    def is_completed(self) -> bool:
        return self.status == ScanStatus.COMPLETED

    # ── Serialización ─────────────────────────────────────────────
    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "name":          self.name,
            "target":        self.target,
            "port_range":    self.port_range,
            "status":        self.status.value,
            "risk_score":    round(self.risk_score or 0.0, 2),
            "severity":      self.severity.value,
            "total_hosts":   self.total_hosts,
            "total_open_ports": self.total_open_ports,
            "total_vulns":   self.total_vulns,
            "total_findings": self.total_findings,
            "notes":         self.notes,
            "created_at":    self.created_at.isoformat() if self.created_at else None,
            "started_at":    self.started_at.isoformat() if self.started_at else None,
            "completed_at":  self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
        }

    def __repr__(self) -> str:
        return f"<Scan id={self.id} target='{self.target}' status={self.status.value}>"


# ══════════════════════════════════════════════════════════════
# MODELO: HOST
# ══════════════════════════════════════════════════════════════

class Host(Base):
    """
    Un host descubierto durante una auditoría.

    Almacena la información de red del equipo (IP, MAC, OS)
    y agrega las métricas de riesgo calculadas a partir de
    sus puertos abiertos y las vulnerabilidades asociadas.
    """
    __tablename__ = "hosts"
    __table_args__ = (
        UniqueConstraint("scan_id", "ip", name="uq_host_scan_ip"),
    )

    id             = Column(Integer, primary_key=True, autoincrement=True)
    scan_id        = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"),
                            nullable=False)
    ip             = Column(String(45), nullable=False,
                            doc="Dirección IPv4 o IPv6 del host")
    hostname       = Column(String(255), nullable=True)
    mac            = Column(String(17), nullable=True,
                            doc="Dirección MAC en formato AA:BB:CC:DD:EE:FF")
    vendor         = Column(String(200), nullable=True,
                            doc="Fabricante derivado del prefijo OUI de la MAC")
    os             = Column(String(200), nullable=True,
                            doc="Sistema operativo detectado (fingerprinting)")
    os_confidence  = Column(Integer, nullable=True,
                            doc="Porcentaje de confianza en la detección de OS (0-100)")
    status         = Column(String(10), default="up",
                            doc="Estado del host: 'up' o 'down'")
    risk_score     = Column(Float, default=0.0)
    open_ports     = Column(Integer, default=0)
    vuln_count     = Column(Integer, default=0)
    finding_count  = Column(Integer, default=0)
    created_at     = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # ── Relaciones ────────────────────────────────────────────────
    scan     = relationship("Scan",    back_populates="hosts")
    ports    = relationship("Port",    back_populates="host",
                            cascade="all, delete-orphan", lazy="dynamic")
    findings = relationship("Finding", back_populates="host",
                            cascade="all, delete-orphan")

    @property
    def severity(self) -> Severity:
        return Severity.from_cvss(self.risk_score)

    @property
    def display_name(self) -> str:
        """Nombre para mostrar: hostname si existe, si no la IP."""
        return self.hostname or self.ip

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "scan_id":       self.scan_id,
            "ip":            self.ip,
            "hostname":      self.hostname,
            "mac":           self.mac,
            "vendor":        self.vendor,
            "os":            self.os,
            "os_confidence": self.os_confidence,
            "status":        self.status,
            "risk_score":    round(self.risk_score or 0.0, 2),
            "severity":      self.severity.value,
            "open_ports":    self.open_ports,
            "vuln_count":    self.vuln_count,
            "finding_count": self.finding_count,
            "created_at":    self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<Host ip='{self.ip}' os='{self.os}' risk={self.risk_score}>"


# ══════════════════════════════════════════════════════════════
# MODELO: PORT
# ══════════════════════════════════════════════════════════════

class Port(Base):
    """
    Un puerto TCP/UDP abierto en un host.

    Almacena el número de puerto, el estado, el servicio
    detectado y el banner capturado.
    """
    __tablename__ = "ports"
    __table_args__ = (
        UniqueConstraint("host_id", "number", "protocol", name="uq_port_host_num_proto"),
    )

    id               = Column(Integer, primary_key=True, autoincrement=True)
    host_id          = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"),
                              nullable=False)
    number           = Column(Integer, nullable=False)
    protocol         = Column(String(5), default="tcp",
                              doc="Protocolo: 'tcp' o 'udp'")
    state            = Column(String(20), default="open",
                              doc="Estado: open, closed, filtered")
    service_name     = Column(String(100), nullable=True,
                              doc="Nombre del servicio (ej: http, ssh, smb)")
    service_version  = Column(String(200), nullable=True,
                              doc="Versión del servicio detectada (ej: Apache 2.4.49)")
    service_banner   = Column(Text, nullable=True,
                              doc="Banner capturado del servicio")
    cpe              = Column(String(300), nullable=True,
                              doc="CPE (Common Platform Enumeration) para búsqueda de CVEs")
    is_dangerous     = Column(Boolean, default=False,
                              doc="Marcado como peligroso por el motor de reglas")
    created_at       = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # ── Relaciones ────────────────────────────────────────────────
    host  = relationship("Host",          back_populates="ports")
    vulns = relationship("Vulnerability", back_populates="port",
                         cascade="all, delete-orphan")

    @property
    def service_display(self) -> str:
        """Texto de servicio para mostrar en la UI."""
        parts = filter(None, [self.service_name, self.service_version])
        return " / ".join(parts) or "Desconocido"

    def to_dict(self) -> dict:
        return {
            "id":              self.id,
            "host_id":         self.host_id,
            "number":          self.number,
            "protocol":        self.protocol,
            "state":           self.state,
            "service_name":    self.service_name,
            "service_version": self.service_version,
            "service_banner":  self.service_banner,
            "cpe":             self.cpe,
            "is_dangerous":    self.is_dangerous,
            "vuln_count":      len(self.vulns) if self.vulns else 0,
            "created_at":      self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<Port {self.number}/{self.protocol} {self.service_name} [{self.state}]>"


# ══════════════════════════════════════════════════════════════
# MODELO: VULNERABILITY
# ══════════════════════════════════════════════════════════════

class Vulnerability(Base):
    """
    Una vulnerabilidad CVE correlacionada con un puerto/servicio.

    Los datos se obtienen de la NVD API (nvd.nist.gov) y se
    almacenan localmente para evitar consultas repetidas.
    """
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("port_id", "cve_id", name="uq_vuln_port_cve"),
    )

    id          = Column(Integer, primary_key=True, autoincrement=True)
    port_id     = Column(Integer, ForeignKey("ports.id", ondelete="CASCADE"),
                         nullable=False)
    cve_id      = Column(String(20), nullable=False,
                         doc="Identificador CVE, ej: CVE-2021-44228")
    cvss_score  = Column(Float, nullable=True,
                         doc="Puntuación CVSS 3.x base score (0.0-10.0)")
    severity    = Column(Enum(Severity), nullable=True)
    vector      = Column(String(200), nullable=True,
                         doc="CVSS vector string, ej: AV:N/AC:L/PR:N/UI:N/...")
    description = Column(Text, nullable=True)
    published   = Column(DateTime, nullable=True)
    references  = Column(Text, nullable=True,
                         doc="JSON: lista de URLs de referencia")
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # ── Relaciones ────────────────────────────────────────────────
    port = relationship("Port", back_populates="vulns")

    @property
    def references_list(self) -> list[str]:
        """Devuelve las referencias como lista Python."""
        if not self.references:
            return []
        try:
            return json.loads(self.references)
        except (json.JSONDecodeError, TypeError):
            return []

    @references_list.setter
    def references_list(self, urls: list[str]) -> None:
        self.references = json.dumps(urls)

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "port_id":     self.port_id,
            "cve_id":      self.cve_id,
            "cvss_score":  self.cvss_score,
            "severity":    self.severity.value if self.severity else None,
            "vector":      self.vector,
            "description": self.description,
            "published":   self.published.isoformat() if self.published else None,
            "references":  self.references_list,
        }

    def __repr__(self) -> str:
        return f"<Vulnerability {self.cve_id} score={self.cvss_score} [{self.severity}]>"


# ══════════════════════════════════════════════════════════════
# MODELO: FINDING
# ══════════════════════════════════════════════════════════════

class Finding(Base):
    """
    Un hallazgo del motor de reglas de detección.

    Las reglas detectan configuraciones peligrosas que no
    tienen por qué tener un CVE asociado: SMBv1 activo,
    FTP sin autenticación, Telnet expuesto, etc.
    """
    __tablename__ = "findings"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    host_id     = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"),
                         nullable=False)
    rule_id     = Column(String(50), nullable=False,
                         doc="Identificador único de la regla, ej: RULE-001")
    rule_name   = Column(String(200), nullable=False)
    severity    = Column(Enum(Severity), nullable=False, default=Severity.MEDIUM)
    description = Column(Text, nullable=False,
                         doc="Explicación del hallazgo en lenguaje natural")
    evidence    = Column(Text, nullable=True,
                         doc="Evidencia técnica que disparó la regla")
    remediation = Column(Text, nullable=True,
                         doc="Recomendación de corrección")
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # ── Relaciones ────────────────────────────────────────────────
    host = relationship("Host", back_populates="findings")

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "host_id":     self.host_id,
            "rule_id":     self.rule_id,
            "rule_name":   self.rule_name,
            "severity":    self.severity.value,
            "description": self.description,
            "evidence":    self.evidence,
            "remediation": self.remediation,
            "created_at":  self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<Finding rule='{self.rule_id}' severity={self.severity.value}>"


# ══════════════════════════════════════════════════════════════
# MODELO: REPORT
# ══════════════════════════════════════════════════════════════

class Report(Base):
    """
    Un informe de auditoría generado a partir de un Scan.

    Puede ser HTML (siempre) o PDF (requiere WeasyPrint).
    El archivo se guarda en el directorio reports/.
    """
    __tablename__ = "reports"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    scan_id    = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"),
                        nullable=False)
    format     = Column(String(10), default="html",
                        doc="Formato del informe: 'html' o 'pdf'")
    filename   = Column(String(255), nullable=True)
    filepath   = Column(String(500), nullable=True)
    size_bytes = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # ── Relaciones ────────────────────────────────────────────────
    scan = relationship("Scan", back_populates="reports")

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "scan_id":    self.scan_id,
            "format":     self.format,
            "filename":   self.filename,
            "filepath":   self.filepath,
            "size_bytes": self.size_bytes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<Report id={self.id} scan_id={self.scan_id} format={self.format}>"
