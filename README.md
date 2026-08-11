# 🛡️ Ciber-Shield

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white"/>
  <img src="https://img.shields.io/badge/SQLAlchemy-2.0-D71F00?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Bootstrap-5.3-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
  <img src="https://github.com/Constan4/Ciber-Shield/actions/workflows/tests.yml/badge.svg" alt="Tests"/>
</p>

<p align="center">
  <b>Plataforma de auditoría de seguridad de red — full-stack, modular y lista para producción.</b><br/>
  Escanea, correlaciona CVEs, detecta amenazas y genera informes profesionales.
</p>

---

## ¿Qué es Ciber-Shield?

Ciber-Shield automatiza el ciclo completo de auditoría de seguridad:

```
  [ Red objetivo ]
        │
        ▼
  ┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
  │   Scanner   │────►│  CVE Engine  │────►│ Detection Rules │
  │  Hosts+Ports│     │  NVD API     │     │  Risk Scoring   │
  └─────────────┘     └──────────────┘     └─────────────────┘
                                                    │
        ┌───────────────────────────────────────────┘
        ▼
  ┌─────────────┐     ┌──────────────┐
  │  Dashboard  │     │   Informes   │
  │  Web + API  │     │  HTML / PDF  │
  └─────────────┘     └──────────────┘
```

---

## ✨ Características

| Módulo | Función |
|--------|---------|
| **Scanner** | Discovery de hosts, escaneo TCP/UDP, detección de servicios y OS fingerprinting |
| **CVE Engine** | Correlación con NVD API v2.0, caché en disco, rate limiting automático |
| **Risk Scorer** | Puntuación CVSS 3.1 a nivel de puerto, host y auditoría completa |
| **Detection Rules** | 18+ reglas: Telnet, SMBv1, Redis/MongoDB sin auth, Docker API, RDP, etc. |
| **REST API** | API Flask completa — integrable en pipelines CI/CD |
| **Dashboard Web** | Dark theme Bootstrap 5 + Chart.js — gráficas de riesgo interactivas |
| **Informes** | HTML/PDF profesionales listos para entregar al cliente |
| **Tests** | pytest con 60+ tests unitarios e integración |

---

## 🚀 Inicio rápido

```bash
git clone https://github.com/Constan4/Ciber-Shield.git
cd Ciber-Shield
pip install -r requirements.txt
python3 app.py init-db

# Escanear tu red
python3 app.py scan --target 192.168.1.0/24 --ports common

# Ver resultados
python3 app.py show-scan --id 1

# Dashboard web
python3 app.py web   # → http://localhost:5000

# Generar informe
python3 app.py report --id 1 --format html
```

📖 Ver **[QUICKSTART.md](QUICKSTART.md)** para la guía completa.

---

## 🏗️ Arquitectura

```
Ciber-Shield/
├── core/         # Config, BD (SQLAlchemy), modelos, logger
├── scanner/      # Discovery → Port scan → Service probe → Orchestrator
├── vuln/         # NVD client → CVE correlator → Risk scorer
├── detect/       # 18+ reglas de detección + motor de evaluación
├── report/       # Generador HTML/PDF profesional
├── api/          # REST API Flask (Blueprints)
├── web/          # Dashboard Bootstrap 5 + Chart.js
├── tests/        # pytest — 60+ tests unitarios e integración
└── app.py        # CLI Click + punto de entrada Flask
```

---

## 🖥️ CLI

```bash
python3 app.py scan     --target IP  --ports common    # Escaneo completo
python3 app.py analyze  --id N                         # Análisis CVE
python3 app.py detect   --id N                         # Motor de reglas
python3 app.py report   --id N --format html           # Generar informe
python3 app.py list-scans                              # Listar auditorías
python3 app.py show-scan --id N                        # Ver detalle
python3 app.py web                                     # Dashboard web
```

## 🔌 REST API

```bash
GET  /api/health                    # Estado de la API
GET  /api/scans                     # Listar auditorías
POST /api/scans                     # Crear y lanzar auditoría
GET  /api/scans/{id}/summary        # Resumen de riesgo
GET  /api/scans/{id}/hosts          # Hosts descubiertos
GET  /api/hosts/{id}/full           # Host completo (puertos+CVEs+hallazgos)
POST /api/scans/{id}/report         # Generar informe
```

---

## 🧪 Tests

```bash
make test        # Todos los tests
make test-fast   # Solo unitarios (sin API)
pytest tests/ -v # Con detalle completo
```

---

## 🛠️ Stack tecnológico

| Capa | Tecnología |
|------|-----------|
| Backend | Python 3.10+, Flask 3.0 |
| ORM / BD | SQLAlchemy 2.0, SQLite |
| Frontend | Bootstrap 5, Chart.js, Jinja2 |
| CLI | Click, Rich |
| Informes | WeasyPrint, Jinja2 |
| APIs externas | NVD (NIST) para CVEs |
| Tests | pytest, pytest-flask |

---

## 📋 Roadmap

- [x] **Core** — Configuración, BD, modelos, logger
- [x] **Scanner** — Discovery, port scan, service probe, orchestrator
- [x] **CVE Engine** — NVD API, correlación, risk scoring
- [x] **Detection Rules** — 18+ reglas + motor de evaluación
- [x] **REST API** — Flask Blueprints completos
- [x] **Dashboard Web** — Bootstrap 5 + Chart.js
- [x] **Report Generator** — HTML/PDF profesional
- [x] **Tests** — pytest con 60+ tests
- [ ] **Docker** — Contenedor para despliegue rápido
- [ ] **CVSS v4.0** — Soporte del nuevo estándar
- [ ] **Active Directory** — Módulo específico para entornos AD

---

## ⚠️ Aviso Legal

> Esta herramienta es para uso exclusivo en auditorías de seguridad **con autorización expresa**.
> El escaneo de redes sin permiso puede ser ilegal. Úsala responsablemente.

---

*Desarrollado por [Constan Millán](https://github.com/Constan4) — Estudiante de Ciberseguridad*
