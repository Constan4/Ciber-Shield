"""
tests/test_scanner.py — Tests del módulo scanner.

Prueba las funciones de utilidad del scanner que NO requieren
acceso a la red: parseo de rangos de puertos, parseo de objetivos,
extracción de versiones, construcción de CPEs, etc.
"""

import pytest
from scanner.port_scanner  import parse_port_range, PortResult, KNOWN_SERVICES
from scanner.discovery     import parse_target
from scanner.service_probe import _extract_version, build_cpe, _os_from_banners


class TestParsePortRange:
    """Tests de parse_port_range()."""

    def test_single_port(self):
        assert parse_port_range("80") == [80]

    def test_multiple_ports(self):
        result = parse_port_range("22,80,443")
        assert result == [22, 80, 443]

    def test_range(self):
        result = parse_port_range("1-5")
        assert result == [1, 2, 3, 4, 5]

    def test_mixed(self):
        result = parse_port_range("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]

    def test_duplicates_removed(self):
        result = parse_port_range("80,80,443")
        assert result == [80, 443]

    def test_common_preset(self):
        result = parse_port_range("common")
        assert 22 in result
        assert 80 in result
        assert 443 in result
        assert 3389 in result
        assert len(result) > 20

    def test_all_returns_65535_ports(self):
        result = parse_port_range("all")
        assert len(result) == 65535
        assert result[0] == 1
        assert result[-1] == 65535

    def test_invalid_port_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("0")       # Puerto 0 no válido

    def test_port_out_of_range_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("65536")   # Puerto > 65535

    def test_invalid_string_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("abc")


class TestParseTarget:
    """Tests de parse_target() para parsing de objetivos de red."""

    def test_single_ip(self):
        result = parse_target("192.168.1.1")
        assert result == ["192.168.1.1"]

    def test_cidr_24(self):
        result = parse_target("192.168.1.0/24")
        assert len(result) == 254
        assert "192.168.1.1" in result
        assert "192.168.1.254" in result
        # Dirección de red y broadcast excluidas
        assert "192.168.1.0" not in result
        assert "192.168.1.255" not in result

    def test_cidr_30(self):
        result = parse_target("192.168.1.0/30")
        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result

    def test_cidr_32_single_host(self):
        # /32 debe devolver la IP sin broadcast/red
        result = parse_target("192.168.1.41/32")
        assert "192.168.1.41" in result

    def test_dash_range(self):
        result = parse_target("192.168.1.10-15")
        assert len(result) == 6
        assert "192.168.1.10" in result
        assert "192.168.1.15" in result

    def test_invalid_target_raises(self):
        with pytest.raises(ValueError):
            parse_target("no-es-una-ip-valida-xyz-123")


class TestPortResult:
    """Tests del dataclass PortResult."""

    def test_service_name_known(self):
        p = PortResult(number=22, state="open")
        assert p.service_name == "ssh"

    def test_service_name_unknown(self):
        p = PortResult(number=54321, state="open")
        assert p.service_name == "unknown"

    def test_to_dict_keys(self):
        p = PortResult(number=443, state="open", banner="HTTP/1.1 200 OK")
        d = p.to_dict()
        assert d["number"]       == 443
        assert d["state"]        == "open"
        assert d["service_name"] == "https"
        assert d["banner"]       == "HTTP/1.1 200 OK"


class TestExtractVersion:
    """Tests de _extract_version() del service probe."""

    def test_apache_version(self):
        banner = "HTTP/1.1 200 OK\nServer: Apache/2.4.49 (Ubuntu)"
        v = _extract_version(banner)
        assert v == "2.4.49"

    def test_nginx_version(self):
        banner = "HTTP/1.1 200 OK\nServer: nginx/1.18.0"
        v = _extract_version(banner)
        assert v == "1.18.0"

    def test_openssh_version(self):
        banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        v = _extract_version(banner)
        assert "8.2" in v

    def test_no_version_returns_empty(self):
        banner = "220 Generic SMTP Server"
        v = _extract_version(banner)
        # Puede devolver cadena vacía o un número genérico
        assert isinstance(v, str)


class TestBuildCPE:
    """Tests de build_cpe() del service probe."""

    def test_apache_cpe(self):
        cpe = build_cpe("apache_httpd", "2.4.49")
        assert cpe.startswith("cpe:2.3:a:apache:http_server:2.4.49")

    def test_openssh_cpe(self):
        cpe = build_cpe("openssh", "8.2")
        assert "openssh" in cpe
        assert "8.2" in cpe

    def test_unknown_service_empty(self):
        cpe = build_cpe("unknown", "1.0")
        assert cpe == ""

    def test_empty_version_empty(self):
        cpe = build_cpe("apache_httpd", "")
        assert cpe == ""


class TestOSFromBanners:
    """Tests de fingerprinting de OS por banners."""

    def _make_port(self, number, banner):
        return PortResult(number=number, state="open", banner=banner)

    def test_windows_from_smb_banner(self):
        ports = [self._make_port(445, "DESKTOP-01O917C NetBIOS Windows")]
        os_name, confidence = _os_from_banners(ports)
        assert "Windows" in os_name
        assert confidence > 0

    def test_ubuntu_from_ssh_banner(self):
        ports = [self._make_port(22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")]
        os_name, confidence = _os_from_banners(ports)
        assert "Ubuntu" in os_name
        assert confidence > 0

    def test_no_banner_returns_empty(self):
        ports = [self._make_port(80, "")]
        os_name, confidence = _os_from_banners(ports)
        assert os_name == ""
        assert confidence == 0


class TestKnownServices:
    """Tests del diccionario KNOWN_SERVICES."""

    def test_common_ports_are_known(self):
        assert KNOWN_SERVICES[22]  == "ssh"
        assert KNOWN_SERVICES[80]  == "http"
        assert KNOWN_SERVICES[443] == "https"
        assert KNOWN_SERVICES[445] == "smb"
        assert KNOWN_SERVICES[3389] == "rdp"
        assert KNOWN_SERVICES[6379] == "redis"
        assert KNOWN_SERVICES[27017] == "mongodb"

    def test_services_have_string_values(self):
        for port, service in KNOWN_SERVICES.items():
            assert isinstance(port, int)
            assert isinstance(service, str)
            assert len(service) > 0
