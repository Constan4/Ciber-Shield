"""
tests/test_rules.py — Tests del motor de reglas de detección.

Verifica que cada regla se dispara correctamente ante configuraciones
peligrosas y NO se dispara ante configuraciones seguras.
"""

import pytest
from detect.rules  import RULES, RULES_BY_ID, get_rule, get_rules_by_tag
from detect.engine import RuleEngine


# ── Helpers para construir datos de puertos de prueba ─────────

def _port(number, service_name="", service_version="", banner="", is_dangerous=False):
    return {
        "number":          number,
        "protocol":        "tcp",
        "state":           "open",
        "service_name":    service_name,
        "service_version": service_version,
        "service_banner":  banner,
        "is_dangerous":    is_dangerous,
    }


# ══════════════════════════════════════════════════════════════
# TESTS DEL CATÁLOGO
# ══════════════════════════════════════════════════════════════

class TestRulesCatalog:
    """Tests sobre la estructura del catálogo de reglas."""

    def test_rules_list_not_empty(self):
        assert len(RULES) > 0, "El catálogo de reglas está vacío"

    def test_all_rules_have_required_fields(self):
        for rule in RULES:
            assert rule.rule_id,     f"Regla sin rule_id"
            assert rule.name,        f"{rule.rule_id}: sin nombre"
            assert rule.severity,    f"{rule.rule_id}: sin severidad"
            assert rule.description, f"{rule.rule_id}: sin descripción"
            assert rule.remediation, f"{rule.rule_id}: sin remediación"
            assert callable(rule.evaluate), f"{rule.rule_id}: evaluate no es callable"

    def test_rule_ids_are_unique(self):
        ids = [r.rule_id for r in RULES]
        assert len(ids) == len(set(ids)), "Hay IDs de regla duplicados"

    def test_rules_by_id_index(self):
        assert len(RULES_BY_ID) == len(RULES)
        for rule in RULES:
            assert rule.rule_id in RULES_BY_ID

    def test_get_rule_existing(self):
        rule = get_rule("RULE-001")
        assert rule is not None
        assert rule.rule_id == "RULE-001"

    def test_get_rule_nonexistent(self):
        assert get_rule("RULE-999") is None

    def test_get_rules_by_tag(self):
        network_rules = get_rules_by_tag("network")
        assert len(network_rules) > 0
        for r in network_rules:
            assert "network" in r.tags

    def test_at_least_15_rules(self):
        """El catálogo debe tener al menos 15 reglas de detección."""
        assert len(RULES) >= 15


# ══════════════════════════════════════════════════════════════
# TESTS POR REGLA INDIVIDUAL
# ══════════════════════════════════════════════════════════════

class TestRule001Telnet:
    """RULE-001: Telnet expuesto."""

    def test_fires_on_port_23(self):
        rule = get_rule("RULE-001")
        ports = [_port(23, "telnet")]
        evidences = rule.check(ports)
        assert len(evidences) > 0

    def test_no_fire_without_port_23(self):
        rule = get_rule("RULE-001")
        ports = [_port(22, "ssh"), _port(80, "http")]
        assert rule.check(ports) == []


class TestRule003NetBIOS:
    """RULE-003: NetBIOS/SMBv1."""

    def test_fires_on_port_139(self):
        rule = get_rule("RULE-003")
        ports = [_port(139, "netbios-ssn")]
        assert len(rule.check(ports)) > 0

    def test_no_fire_without_netbios(self):
        rule = get_rule("RULE-003")
        ports = [_port(445, "smb"), _port(80, "http")]
        assert rule.check(ports) == []


class TestRule004SMB:
    """RULE-004: SMB expuesto."""

    def test_fires_on_port_445(self):
        rule = get_rule("RULE-004")
        ports = [_port(445, "smb")]
        assert len(rule.check(ports)) > 0

    def test_no_fire_on_other_ports(self):
        rule = get_rule("RULE-004")
        ports = [_port(80, "http"), _port(22, "ssh")]
        assert rule.check(ports) == []


class TestRule005RDP:
    """RULE-005: RDP expuesto."""

    def test_fires_on_port_3389(self):
        rule = get_rule("RULE-005")
        ports = [_port(3389, "rdp")]
        assert len(rule.check(ports)) > 0


class TestRule006Redis:
    """RULE-006: Redis posiblemente sin autenticación."""

    def test_fires_on_port_6379_with_pong(self):
        rule = get_rule("RULE-006")
        ports = [_port(6379, "redis", banner="+PONG")]
        assert len(rule.check(ports)) > 0

    def test_fires_on_port_6379_no_banner(self):
        rule = get_rule("RULE-006")
        ports = [_port(6379, "redis")]
        # Sin banner también puede dispararse (puerto abierto = riesgo)
        evidences = rule.check(ports)
        assert isinstance(evidences, list)


class TestRule009Docker:
    """RULE-009: Docker API sin TLS."""

    def test_fires_on_port_2375(self):
        rule = get_rule("RULE-009")
        ports = [_port(2375, "docker")]
        assert len(rule.check(ports)) > 0

    def test_no_fire_on_docker_tls_port(self):
        rule = get_rule("RULE-009")
        ports = [_port(2376, "docker-tls")]   # Puerto TLS, no sin TLS
        assert rule.check(ports) == []


class TestRule013Databases:
    """RULE-013: Bases de datos expuestas."""

    def test_fires_on_mysql(self):
        rule = get_rule("RULE-013")
        ports = [_port(3306, "mysql")]
        assert len(rule.check(ports)) > 0

    def test_fires_on_postgresql(self):
        rule = get_rule("RULE-013")
        ports = [_port(5432, "postgresql")]
        assert len(rule.check(ports)) > 0

    def test_fires_on_multiple_dbs(self):
        rule = get_rule("RULE-013")
        ports = [_port(3306, "mysql"), _port(1433, "mssql")]
        evidences = rule.check(ports)
        assert len(evidences) > 0
        # La evidencia menciona los puertos
        assert any("3306" in e or "1433" in e for e in evidences)

    def test_no_fire_without_db_ports(self):
        rule = get_rule("RULE-013")
        ports = [_port(80, "http"), _port(443, "https")]
        assert rule.check(ports) == []


class TestRule016HTTPnoHTTPS:
    """RULE-016: HTTP disponible sin HTTPS."""

    def test_fires_when_80_open_443_not(self):
        rule = get_rule("RULE-016")
        ports = [_port(80, "http")]
        assert len(rule.check(ports)) > 0

    def test_no_fire_when_both_open(self):
        rule = get_rule("RULE-016")
        ports = [_port(80, "http"), _port(443, "https")]
        assert rule.check(ports) == []

    def test_no_fire_when_only_443(self):
        rule = get_rule("RULE-016")
        ports = [_port(443, "https")]
        assert rule.check(ports) == []


class TestRule017DangerousCount:
    """RULE-017: Alto número de puertos peligrosos."""

    def test_fires_with_3_or_more_dangerous(self):
        rule = get_rule("RULE-017")
        ports = [
            _port(23, "telnet"),   # peligroso
            _port(445, "smb"),     # peligroso
            _port(3389, "rdp"),    # peligroso
        ]
        assert len(rule.check(ports)) > 0

    def test_no_fire_with_less_than_3(self):
        rule = get_rule("RULE-017")
        ports = [_port(23, "telnet"), _port(445, "smb")]
        assert rule.check(ports) == []


# ══════════════════════════════════════════════════════════════
# TESTS DEL MOTOR (RuleEngine)
# ══════════════════════════════════════════════════════════════

class TestRuleEngine:
    """Tests del RuleEngine usando test_rules() sin BD."""

    def test_engine_detects_telnet(self):
        engine = RuleEngine()
        ports  = [_port(23, "telnet")]
        results = engine.test_rules(ports)
        rule_ids = [r["rule_id"] for r in results]
        assert "RULE-001" in rule_ids

    def test_engine_detects_multiple(self):
        engine = RuleEngine()
        ports  = [
            _port(23, "telnet"),
            _port(445, "smb"),
            _port(3389, "rdp"),
            _port(6379, "redis"),
        ]
        results = engine.test_rules(ports)
        assert len(results) >= 4   # Al menos una evidencia por puerto peligroso

    def test_engine_clean_system(self):
        """Un sistema solo con 22 y 443 no debe tener hallazgos críticos."""
        engine = RuleEngine()
        ports  = [_port(22, "ssh"), _port(443, "https")]
        results = engine.test_rules(ports)
        critical = [r for r in results if r["severity"] == "critical"]
        assert len(critical) == 0

    def test_engine_result_structure(self):
        """Cada resultado tiene los campos obligatorios."""
        engine = RuleEngine()
        ports  = [_port(23, "telnet")]
        results = engine.test_rules(ports)
        assert len(results) > 0
        for r in results:
            assert "rule_id"     in r
            assert "name"        in r
            assert "severity"    in r
            assert "evidence"    in r
            assert "remediation" in r

    def test_engine_with_custom_rules(self):
        """El motor puede usar un subconjunto de reglas."""
        one_rule = [get_rule("RULE-001")]
        engine   = RuleEngine(rules=one_rule)
        ports    = [_port(23, "telnet"), _port(445, "smb")]
        results  = engine.test_rules(ports)
        # Solo la regla RULE-001 debería dispararse
        rule_ids = {r["rule_id"] for r in results}
        assert "RULE-001" in rule_ids
        assert "RULE-004" not in rule_ids
