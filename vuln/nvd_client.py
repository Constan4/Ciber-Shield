"""
vuln/nvd_client.py — Cliente de la NVD API v2.0.

Funcionalidades:
    - Búsqueda de CVEs por keyword (software + versión) o por CPE
    - Caché en disco (JSON) con TTL de 24h para evitar peticiones repetidas
    - Control automático de rate-limit (5 req/30s sin key, 50 con key)
    - Reintentos con espera exponencial ante errores HTTP 403/429/5xx
    - Parsing estructurado de respuestas NVD → dicts normalizados

NVD API docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from core.config import Config
from core.logger import get_logger

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════

NVD_API_URL      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL        = 86_400        # 24 horas en segundos
MAX_RETRIES      = 3
RETRY_BASE_WAIT  = 2.0           # segundos (se duplica en cada intento)
REQUEST_TIMEOUT  = 30            # segundos por petición HTTP

#: Preferencia de métricas CVSS (más reciente primero)
CVSS_METRIC_KEYS = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"]


# ══════════════════════════════════════════════════════════════
# RATE LIMITER
# ══════════════════════════════════════════════════════════════

class _RateLimiter:
    """
    Controla la tasa de peticiones para respetar los límites de la NVD API.

    Sin API key: 5 peticiones / 30 segundos.
    Con API key: 50 peticiones / 30 segundos.
    """

    def __init__(self, has_api_key: bool = False) -> None:
        self.max_requests = 50 if has_api_key else 5
        self.window       = 30.0   # segundos
        self._timestamps: List[float] = []

    def wait_if_needed(self) -> None:
        """Bloquea el hilo hasta que sea seguro hacer la próxima petición."""
        now = time.monotonic()

        # Eliminar timestamps fuera de la ventana
        self._timestamps = [
            t for t in self._timestamps if now - t < self.window
        ]

        if len(self._timestamps) >= self.max_requests:
            oldest    = self._timestamps[0]
            wait_secs = self.window - (now - oldest) + 0.1
            if wait_secs > 0:
                logger.debug(
                    f"NVD rate-limit alcanzado ({self.max_requests} req/{self.window}s). "
                    f"Esperando {wait_secs:.1f}s..."
                )
                time.sleep(wait_secs)

        self._timestamps.append(time.monotonic())


# ══════════════════════════════════════════════════════════════
# CACHÉ EN DISCO
# ══════════════════════════════════════════════════════════════

class _DiskCache:
    """
    Caché simple basada en archivos JSON.

    La clave es el MD5 de los parámetros de la petición.
    Cada entrada tiene un timestamp; las entradas más antiguas que
    CACHE_TTL se consideran expiradas y se ignoran.
    """

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _key(self, params: dict) -> str:
        """Genera el identificador de caché a partir de los parámetros."""
        serialized = json.dumps(params, sort_keys=True)
        return hashlib.md5(serialized.encode()).hexdigest()

    def get(self, params: dict) -> Optional[dict]:
        """Devuelve los datos en caché si existen y no han expirado."""
        path = self.cache_dir / f"{self._key(params)}.json"
        if not path.exists():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
            cached_at = entry.get("_cached_at", 0)
            if time.time() - cached_at > CACHE_TTL:
                path.unlink(missing_ok=True)
                return None
            return entry.get("data")
        except (json.JSONDecodeError, KeyError, OSError):
            return None

    def set(self, params: dict, data: dict) -> None:
        """Guarda los datos en caché con timestamp."""
        path = self.cache_dir / f"{self._key(params)}.json"
        try:
            entry = {"_cached_at": time.time(), "data": data}
            path.write_text(json.dumps(entry), encoding="utf-8")
        except OSError as e:
            logger.debug(f"Cache write error: {e}")

    def clear(self) -> int:
        """Elimina todas las entradas de caché. Devuelve el número eliminado."""
        count = 0
        for f in self.cache_dir.glob("*.json"):
            try:
                f.unlink()
                count += 1
            except OSError:
                pass
        return count

    def stats(self) -> dict:
        files  = list(self.cache_dir.glob("*.json"))
        now    = time.time()
        valid  = 0
        for f in files:
            try:
                entry = json.loads(f.read_text())
                if now - entry.get("_cached_at", 0) <= CACHE_TTL:
                    valid += 1
            except Exception:
                pass
        return {"total": len(files), "valid": valid, "expired": len(files) - valid}


# ══════════════════════════════════════════════════════════════
# CLIENTE PRINCIPAL
# ══════════════════════════════════════════════════════════════

class NVDClient:
    """
    Cliente completo para la NVD API v2.0.

    Uso:
        client = NVDClient()                        # sin API key
        client = NVDClient(api_key="TU_KEY")        # con API key

        cves = client.search_by_keyword("apache httpd 2.4.49")
        cves = client.search_by_cpe("cpe:2.3:a:apache:http_server:2.4.49:*")
    """

    def __init__(
        self,
        api_key:   str            = "",
        cache_dir: Optional[Path] = None,
    ) -> None:
        self.api_key   = api_key or Config.NVD_API_KEY
        self._cache    = _DiskCache(cache_dir or Config.DATA_DIR / "nvd_cache")
        self._limiter  = _RateLimiter(has_api_key=bool(self.api_key))

        logger.debug(
            f"NVDClient inicializado — "
            f"API key: {'configurada' if self.api_key else 'no configurada'}, "
            f"Rate limit: {self._limiter.max_requests} req/{self._limiter.window}s"
        )

    # ── API pública ──────────────────────────────────────────

    def search_by_keyword(
        self,
        keyword:     str,
        max_results: int = 20,
    ) -> List[dict]:
        """
        Busca CVEs que coincidan con una o más palabras clave.

        Args:
            keyword:     Término de búsqueda (ej: "apache httpd 2.4.49").
            max_results: Número máximo de resultados a devolver.

        Returns:
            Lista de dicts CVE normalizados, ordenados por CVSS descendente.
        """
        if not keyword or not keyword.strip():
            return []

        params = {
            "keywordSearch":  keyword.strip(),
            "resultsPerPage": min(max_results, 2000),
            "startIndex":     0,
        }

        logger.debug(f"NVD search_by_keyword: '{keyword}' (max={max_results})")
        raw = self._cached_request(params)
        if raw is None:
            return []

        return self._parse_response(raw, max_results)

    def search_by_cpe(
        self,
        cpe:         str,
        max_results: int = 20,
    ) -> List[dict]:
        """
        Busca CVEs por CPE (Common Platform Enumeration).

        Más preciso que keyword, pero requiere un CPE bien formado.

        Args:
            cpe:         CPE en formato 2.3 (ej: cpe:2.3:a:apache:http_server:2.4.49:*).
            max_results: Número máximo de resultados.

        Returns:
            Lista de dicts CVE normalizados.
        """
        if not cpe or not cpe.startswith("cpe:"):
            return []

        params = {
            "cpeName":        cpe,
            "resultsPerPage": min(max_results, 2000),
            "startIndex":     0,
        }

        logger.debug(f"NVD search_by_cpe: '{cpe}' (max={max_results})")
        raw = self._cached_request(params)
        if raw is None:
            return []

        return self._parse_response(raw, max_results)

    def get_cve(self, cve_id: str) -> Optional[dict]:
        """
        Obtiene los detalles de un CVE específico por su ID.

        Args:
            cve_id: Identificador CVE (ej: "CVE-2021-44228").

        Returns:
            Dict normalizado del CVE o None si no se encuentra.
        """
        params = {"cveId": cve_id.upper().strip()}
        raw    = self._cached_request(params)
        if not raw:
            return None
        results = self._parse_response(raw, 1)
        return results[0] if results else None

    # ── Caché y HTTP ─────────────────────────────────────────

    def _cached_request(self, params: dict) -> Optional[dict]:
        """Intenta obtener la respuesta de la caché; si falla, hace la petición HTTP."""
        cached = self._cache.get(params)
        if cached is not None:
            logger.debug(f"NVD cache HIT — params: {list(params.keys())}")
            return cached

        logger.debug(f"NVD cache MISS — haciendo petición HTTP")
        data = self._make_request(params)

        if data is not None:
            self._cache.set(params, data)

        return data

    def _make_request(self, params: dict) -> Optional[dict]:
        """
        Realiza la petición HTTP a la NVD API con rate limiting y reintentos.

        Returns:
            Dict con la respuesta JSON de la NVD, o None si falla tras los reintentos.
        """
        url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"

        headers: Dict[str, str] = {
            "User-Agent": f"Ciber-Shield/{Config.VERSION}",
            "Accept":     "application/json",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        wait = RETRY_BASE_WAIT

        for attempt in range(1, MAX_RETRIES + 1):
            self._limiter.wait_if_needed()

            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    logger.debug(
                        f"NVD respuesta OK — "
                        f"totalResults: {data.get('totalResults', '?')}"
                    )
                    return data

            except urllib.error.HTTPError as e:
                if e.code in (403, 429):
                    # Rate limit de la API
                    logger.warning(
                        f"NVD rate-limit (HTTP {e.code}), "
                        f"intento {attempt}/{MAX_RETRIES}, "
                        f"esperando {wait:.0f}s"
                    )
                    time.sleep(wait)
                    wait *= 2
                elif e.code >= 500:
                    logger.warning(
                        f"NVD error servidor (HTTP {e.code}), "
                        f"intento {attempt}/{MAX_RETRIES}"
                    )
                    time.sleep(wait)
                    wait *= 2
                else:
                    logger.error(f"NVD HTTP error {e.code}: {e.reason}")
                    return None

            except urllib.error.URLError as e:
                logger.warning(
                    f"NVD conexión fallida (intento {attempt}/{MAX_RETRIES}): {e.reason}"
                )
                time.sleep(wait)
                wait *= 2

            except json.JSONDecodeError as e:
                logger.error(f"NVD respuesta JSON inválida: {e}")
                return None

            except Exception as e:
                logger.error(f"NVD error inesperado: {e}")
                return None

        logger.error(f"NVD: todos los reintentos fallaron para params={list(params.keys())}")
        return None

    # ── Parsing ──────────────────────────────────────────────

    def _parse_response(self, raw: dict, max_results: int) -> List[dict]:
        """
        Transforma la respuesta cruda de la NVD en una lista de dicts normalizados.

        Solo devuelve CVEs con puntuación CVSS, ordenados de mayor a menor.
        """
        vulns = raw.get("vulnerabilities", [])
        results: List[dict] = []

        for entry in vulns[:max_results * 3]:  # parsear más, filtrar después
            parsed = self._parse_cve_entry(entry)
            if parsed and parsed.get("cvss_score") is not None:
                results.append(parsed)

        # Ordenar por CVSS descendente
        results.sort(key=lambda c: c.get("cvss_score") or 0.0, reverse=True)
        return results[:max_results]

    @staticmethod
    def _parse_cve_entry(entry: dict) -> Optional[dict]:
        """
        Extrae los campos relevantes de una entrada CVE de la NVD.

        Returns:
            Dict con los campos normalizados, o None si hay error de parsing.
        """
        try:
            cve = entry.get("cve", {})
            if not cve:
                return None

            cve_id = cve.get("id", "")
            if not cve_id:
                return None

            # ── Descripción (inglés primero) ──────────────────
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "").strip()
                    break

            # ── Métricas CVSS ─────────────────────────────────
            cvss_score  = None
            cvss_vector = ""
            severity    = ""
            metrics = cve.get("metrics", {})

            for key in CVSS_METRIC_KEYS:
                entries = metrics.get(key, [])
                if not entries:
                    continue
                # Preferir "Primary"
                m = next(
                    (e for e in entries if e.get("type") == "Primary"),
                    entries[0]
                )
                data = m.get("cvssData", {})
                cvss_score  = data.get("baseScore")
                cvss_vector = data.get("vectorString", "")
                severity    = (
                    data.get("baseSeverity")
                    or m.get("baseSeverity", "")
                ).upper()
                if cvss_score is not None:
                    break

            # ── Fecha de publicación ──────────────────────────
            published_str = cve.get("published", "")
            published = None
            if published_str:
                try:
                    published = datetime.fromisoformat(
                        published_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            # ── CWEs ──────────────────────────────────────────
            cwes = []
            for weakness in cve.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    val = desc.get("value", "")
                    if val and val not in ("NVD-CWE-noinfo", "NVD-CWE-Other"):
                        cwes.append(val)

            # ── Referencias (primeras 5) ──────────────────────
            references = [
                r.get("url", "")
                for r in cve.get("references", [])[:5]
                if r.get("url")
            ]

            return {
                "cve_id":      cve_id,
                "cvss_score":  float(cvss_score) if cvss_score is not None else None,
                "severity":    severity or "UNKNOWN",
                "vector":      cvss_vector,
                "description": description[:1000],
                "published":   published,
                "cwes":        cwes,
                "references":  references,
            }

        except Exception as e:
            logger.debug(f"Error parsing CVE entry: {e}")
            return None

    # ── Utilidades ────────────────────────────────────────────

    def cache_stats(self) -> dict:
        """Devuelve estadísticas de la caché en disco."""
        return self._cache.stats()

    def clear_cache(self) -> int:
        """Limpia la caché en disco. Devuelve el número de entradas eliminadas."""
        count = self._cache.clear()
        logger.info(f"Caché NVD limpiada — {count} entrada(s) eliminada(s)")
        return count
