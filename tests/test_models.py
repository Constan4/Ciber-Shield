"""
tests/test_models.py — Tests de los modelos de base de datos.

Verifica que los modelos SQLAlchemy se comportan correctamente:
    - Creación y persistencia
    - Relaciones entre entidades
    - Propiedades calculadas (severity, risk_label...)
    - Método to_dict() para la API
"""

import pytest
from datetime import datetime, timezone

from core.database import get_session
from core.models   import (
    Scan, ScanStatus, Host, Port,
    Vulnerability, Finding, Report, Severity,
)


class TestSeverity:
    """Tests del enum Severity y sus métodos auxiliares."""

    def test_from_cvss_critical(self):
        assert Severity.from_cvss(9.8) == Severity.CRITICAL
        assert Severity.from_cvss(10.0) == Severity.CRITICAL
        assert Severity.from_cvss(9.0) == Severity.CRITICAL

    def test_from_cvss_high(self):
        assert Severity.from_cvss(8.9) == Severity.HIGH
        assert Severity.from_cvss(7.0) == Severity.HIGH
        assert Severity.from_cvss(7.5) == Severity.HIGH

    def test_from_cvss_medium(self):
        assert Severity.from_cvss(6.9) == Severity.MEDIUM
        assert Severity.from_cvss(4.0) == Severity.MEDIUM

    def test_from_cvss_low(self):
        assert Severity.from_cvss(3.9) == Severity.LOW
        assert Severity.from_cvss(0.1) == Severity.LOW

    def test_from_cvss_none(self):
        assert Severity.from_cvss(0.0) == Severity.NONE
        assert Severity.from_cvss(None) == Severity.NONE

    def test_color_property(self):
        assert Severity.CRITICAL.color == "danger"
        assert Severity.HIGH.color     == "warning"
        assert Severity.MEDIUM.color   == "info"
        assert Severity.LOW.color      == "secondary"


class TestScanModel:
    """Tests del modelo Scan."""

    def test_create_scan(self, db_engine):
        """Un Scan se crea correctamente y tiene el estado por defecto."""
        with get_session() as session:
            scan = Scan(name="Test", target="192.168.1.0/24")
            session.add(scan)
            session.flush()
            scan_id = scan.id

        with get_session() as session:
            loaded = session.get(Scan, scan_id)
            assert loaded is not None
            assert loaded.name   == "Test"
            assert loaded.target == "192.168.1.0/24"
            assert loaded.status == ScanStatus.PENDING
            assert loaded.risk_score == 0.0

    def test_scan_severity_property(self, db_engine):
        """La propiedad severity se calcula correctamente del risk_score."""
        with get_session() as session:
            scan = Scan(name="Critical scan", target="10.0.0.1", risk_score=9.5)
            session.add(scan); session.flush()
            assert scan.severity == Severity.CRITICAL

        with get_session() as session:
            scan = Scan(name="Safe scan", target="10.0.0.2", risk_score=0.0)
            session.add(scan); session.flush()
            assert scan.severity == Severity.NONE

    def test_scan_to_dict(self, db_engine):
        """to_dict() devuelve todos los campos esperados."""
        with get_session() as session:
            scan = Scan(
                name="Dict test", target="192.168.1.1",
                status=ScanStatus.COMPLETED, risk_score=7.2,
            )
            session.add(scan); session.flush()
            d = scan.to_dict()

        assert "id" in d
        assert d["name"]       == "Dict test"
        assert d["target"]     == "192.168.1.1"
        assert d["risk_score"] == 7.2
        assert d["severity"]   == "high"
        assert d["status"]     == "completed"

    def test_scan_duration(self, db_engine):
        """La propiedad duration_seconds calcula correctamente."""
        from datetime import timedelta
        start = datetime(2026, 1, 1, 10, 0, 0)
        end   = datetime(2026, 1, 1, 10, 5, 30)

        with get_session() as session:
            scan = Scan(name="Duration", target="1.2.3.4",
                        started_at=start, completed_at=end)
            session.add(scan); session.flush()
            assert scan.duration_seconds == 330.0  # 5 min 30 sec


class TestHostModel:
    """Tests del modelo Host."""

    def test_create_host(self, sample_scan):
        """Un Host se crea y se asocia correctamente a un Scan."""
        with get_session() as session:
            host = Host(
                scan_id=sample_scan, ip="10.0.0.1",
                os="Linux", risk_score=5.5,
            )
            session.add(host); session.flush()
            host_id = host.id

        with get_session() as session:
            h = session.get(Host, host_id)
            assert h.ip        == "10.0.0.1"
            assert h.scan_id   == sample_scan
            assert h.risk_score == 5.5

    def test_host_display_name(self, sample_scan):
        """display_name usa hostname si existe, ip en caso contrario."""
        with get_session() as session:
            h1 = Host(scan_id=sample_scan, ip="1.1.1.1", hostname="servidor.local")
            h2 = Host(scan_id=sample_scan, ip="2.2.2.2")
            session.add_all([h1, h2]); session.flush()
            assert h1.display_name == "servidor.local"
            assert h2.display_name == "2.2.2.2"

    def test_host_to_dict_keys(self, sample_host):
        """to_dict() incluye todos los campos necesarios para la API."""
        with get_session() as session:
            h = session.get(Host, sample_host)
            d = h.to_dict()

        expected_keys = ["id","scan_id","ip","hostname","os","risk_score",
                         "severity","open_ports","vuln_count","finding_count"]
        for key in expected_keys:
            assert key in d, f"Falta la clave '{key}' en to_dict()"


class TestPortModel:
    """Tests del modelo Port."""

    def test_create_port(self, sample_host):
        """Un Port se crea con los valores por defecto correctos."""
        with get_session() as session:
            p = Port(host_id=sample_host, number=443, service_name="https")
            session.add(p); session.flush()
            port_id = p.id

        with get_session() as session:
            p = session.get(Port, port_id)
            assert p.number       == 443
            assert p.protocol     == "tcp"
            assert p.state        == "open"
            assert p.service_name == "https"

    def test_port_service_display(self, sample_host):
        """service_display combina nombre y versión correctamente."""
        with get_session() as session:
            p1 = Port(host_id=sample_host, number=80,
                      service_name="http", service_version="Apache/2.4.49")
            p2 = Port(host_id=sample_host, number=22, service_name="ssh")
            session.add_all([p1, p2]); session.flush()
            assert "Apache" in p1.service_display
            assert p2.service_display == "ssh"


class TestVulnerabilityModel:
    """Tests del modelo Vulnerability."""

    def test_references_list_property(self, sample_host):
        """La propiedad references_list serializa/deserializa JSON."""
        import json

        urls = ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "https://github.com/advisories/GHSA-test"]

        with get_session() as session:
            port = Port(host_id=sample_host, number=8080)
            session.add(port); session.flush()

            v = Vulnerability(
                port_id    = port.id,
                cve_id     = "CVE-2021-44228",
                cvss_score = 10.0,
                severity   = Severity.CRITICAL,
            )
            v.references_list = urls
            session.add(v); session.flush()
            vuln_id = v.id

        with get_session() as session:
            v = session.get(Vulnerability, vuln_id)
            assert v.references_list == urls
            assert v.cvss_score == 10.0
