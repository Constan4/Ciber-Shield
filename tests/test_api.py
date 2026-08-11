"""
tests/test_api.py — Tests de integración de la REST API.

Prueba los endpoints Flask usando el cliente de test de Flask.
Verifica respuestas HTTP, estructura JSON y lógica de negocio básica.
"""

import json
import pytest

from core.database import get_session
from core.models   import Scan, ScanStatus


@pytest.fixture(scope="module")
def flask_app(db_engine):
    """Crea la app Flask configurada para tests."""
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    # Importar create_app DESPUÉS de haber sobrescrito DATABASE_URL
    from app import create_app
    app = create_app()
    app.config["TESTING"]    = True
    app.config["DEBUG"]      = False
    return app


@pytest.fixture
def client(flask_app):
    """Cliente de test de Flask."""
    with flask_app.test_client() as c:
        yield c


# ══════════════════════════════════════════════════════════════
# HEALTH CHECK
# ══════════════════════════════════════════════════════════════

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_health_returns_ok_status(self, client):
        data = json.loads(resp := client.get("/api/health")).data
        # resp.data es bytes, parsear
        data = json.loads(client.get("/api/health").data)
        assert data["status"] == "ok"

    def test_health_has_database_info(self, client):
        data = json.loads(client.get("/api/health").data)
        assert "database" in data["data"]
        assert data["data"]["database"]["status"] == "ok"


# ══════════════════════════════════════════════════════════════
# SCANS API
# ══════════════════════════════════════════════════════════════

class TestScansListEndpoint:
    def test_list_scans_empty(self, client):
        """Lista vacía al inicio."""
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "ok"
        assert data["data"]["total"] == 0
        assert data["data"]["scans"] == []

    def test_list_scans_returns_created_scan(self, client, sample_scan):
        resp = client.get("/api/scans")
        data = json.loads(resp.data)
        assert data["data"]["total"] == 1
        assert data["data"]["scans"][0]["id"] == sample_scan

    def test_list_scans_pagination(self, client):
        """Los parámetros de paginación funcionan."""
        resp = client.get("/api/scans?page=1&per_page=5")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "page"     in data["data"]
        assert "per_page" in data["data"]

    def test_list_scans_filter_by_status(self, client, sample_scan):
        resp = client.get("/api/scans?status=completed")
        data = json.loads(resp.data)
        scans = data["data"]["scans"]
        for s in scans:
            assert s["status"] == "completed"


class TestScanDetailEndpoint:
    def test_get_existing_scan(self, client, sample_scan):
        resp = client.get(f"/api/scans/{sample_scan}")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["data"]["id"] == sample_scan

    def test_get_nonexistent_scan_returns_404(self, client):
        resp = client.get("/api/scans/99999")
        assert resp.status_code == 404

    def test_scan_detail_has_expected_fields(self, client, sample_scan):
        data = json.loads(client.get(f"/api/scans/{sample_scan}").data)
        scan = data["data"]
        for field in ["id","name","target","status","risk_score","total_hosts"]:
            assert field in scan, f"Falta campo '{field}'"


class TestScanHostsEndpoint:
    def test_hosts_returns_list(self, client, sample_scan):
        resp = client.get(f"/api/scans/{sample_scan}/hosts")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "hosts" in data["data"]
        assert "total" in data["data"]

    def test_hosts_for_nonexistent_scan(self, client):
        resp = client.get("/api/scans/99999/hosts")
        assert resp.status_code == 404


class TestDeleteScanEndpoint:
    def test_delete_completed_scan(self, client, sample_scan):
        resp = client.delete(f"/api/scans/{sample_scan}")
        assert resp.status_code == 200
        # Verificar que ya no existe
        resp2 = client.get(f"/api/scans/{sample_scan}")
        assert resp2.status_code == 404

    def test_delete_nonexistent_scan(self, client):
        resp = client.delete("/api/scans/99999")
        assert resp.status_code == 404

    def test_delete_running_scan_returns_409(self, client):
        """No se puede eliminar un scan en ejecución."""
        with get_session() as session:
            scan = Scan(name="Running", target="10.0.0.1",
                        status=ScanStatus.RUNNING)
            session.add(scan); session.flush()
            scan_id = scan.id

        resp = client.delete(f"/api/scans/{scan_id}")
        assert resp.status_code == 409


# ══════════════════════════════════════════════════════════════
# HOSTS API
# ══════════════════════════════════════════════════════════════

class TestHostDetailEndpoint:
    def test_get_existing_host(self, client, sample_host):
        resp = client.get(f"/api/hosts/{sample_host}")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["data"]["ip"] == "192.168.1.41"

    def test_get_nonexistent_host_returns_404(self, client):
        resp = client.get("/api/hosts/99999")
        assert resp.status_code == 404

    def test_host_ports_endpoint(self, client, sample_host):
        resp = client.get(f"/api/hosts/{sample_host}/ports")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "ports" in data["data"]

    def test_host_vulnerabilities_endpoint(self, client, sample_host):
        resp = client.get(f"/api/hosts/{sample_host}/vulnerabilities")
        assert resp.status_code == 200

    def test_host_findings_endpoint(self, client, sample_host):
        resp = client.get(f"/api/hosts/{sample_host}/findings")
        assert resp.status_code == 200

    def test_host_full_endpoint(self, client, sample_host):
        resp = client.get(f"/api/hosts/{sample_host}/full")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        d = data["data"]
        assert "host" in d
        assert "ports" in d
        assert "vulnerabilities" in d
        assert "findings" in d


# ══════════════════════════════════════════════════════════════
# ERROR HANDLING
# ══════════════════════════════════════════════════════════════

class TestErrorHandling:
    def test_invalid_json_body(self, client):
        resp = client.post("/api/scans",
                           data="not json",
                           content_type="application/json")
        # Debe manejar el error sin crashear
        assert resp.status_code in (400, 422)

    def test_missing_required_fields(self, client):
        resp = client.post("/api/scans",
                           json={"name": "Test"},  # falta 'target'
                           content_type="application/json")
        assert resp.status_code == 422
        data = json.loads(resp.data)
        assert data["status"] == "error"
        assert "target" in data["message"]
