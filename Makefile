# ══════════════════════════════════════════════════════════════
#   Makefile — Ciber-Shield
#   Comandos habituales para desarrollo y uso
# ══════════════════════════════════════════════════════════════

.PHONY: install init scan web report test test-fast clean help

PYTHON = python3
TARGET ?= 192.168.1.0/24
PORTS  ?= common
SCAN_ID ?= 1

help:
	@echo ""
	@echo "  🛡️  Ciber-Shield — Comandos disponibles"
	@echo ""
	@echo "  Configuración:"
	@echo "    make install        Instalar dependencias pip"
	@echo "    make init           Inicializar base de datos"
	@echo ""
	@echo "  Uso:"
	@echo "    make scan           Escaneo completo (TARGET=IP PORTS=rango)"
	@echo "    make web            Lanzar dashboard web en :5000"
	@echo "    make report         Generar informe HTML (SCAN_ID=N)"
	@echo ""
	@echo "  Tests:"
	@echo "    make test           Ejecutar todos los tests"
	@echo "    make test-fast      Tests sin los de integración"
	@echo ""
	@echo "  Ejemplos:"
	@echo "    make scan TARGET=192.168.1.41 PORTS=common"
	@echo "    make scan TARGET=192.168.1.0/24 PORTS=1-1024"
	@echo "    make report SCAN_ID=1"
	@echo ""

install:
	pip install -r requirements.txt

init:
	$(PYTHON) app.py init-db

scan:
	$(PYTHON) app.py scan --target $(TARGET) --ports $(PORTS)

web:
	$(PYTHON) app.py web

report:
	$(PYTHON) app.py report --id $(SCAN_ID) --format html

test:
	pytest tests/ -v --tb=short

test-fast:
	pytest tests/test_models.py tests/test_scanner.py tests/test_rules.py -v --tb=short

clean:
	rm -rf data/ logs/ reports/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
