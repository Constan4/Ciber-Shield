"""
detect — Motor de detección de reglas de Ciber-Shield.

Módulos:
    rules.py  → Catálogo de 18+ reglas de detección
    engine.py → Motor de evaluación con persistencia en BD
"""
from .rules  import RULES, Rule, RULES_BY_ID, get_rule, get_rules_by_tag
from .engine import RuleEngine, run_detection

__all__ = [
    "RULES", "Rule", "RULES_BY_ID",
    "get_rule", "get_rules_by_tag",
    "RuleEngine", "run_detection",
]
