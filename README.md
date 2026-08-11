# 🛡️ Ciber-Shield

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white"/>
  <img src="https://img.shields.io/badge/SQLAlchemy-2.0-D71F00?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Bootstrap-5.3-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
</p>

<p align="center">
  <b>Plataforma de auditoría de seguridad de red — full-stack, modular y lista para producción.</b><br/>
  Escanea, correlaciona CVEs, detecta amenazas y genera informes profesionales.
</p>

---

## ¿Qué es Ciber-Shield?

Ciber-Shield es una **plataforma de auditoría de seguridad** que automatiza el ciclo completo de análisis de una red o sistema:

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
| **Scanner** | Descubrimiento de hosts, escaneo de puertos TCP/UDP, detección de servicios y OS |
| **CVE Engine** | Correlación automática de servicios con vulnerabilidades reales (NVD API) |
| **Risk Scorer** | Puntuación de riesgo basada en CVSS 3.1 a nivel de puerto, host y auditoría |
| **Detection Rules** | Motor de reglas para detectar configuraciones peligrosas (SMBv1, FTP anónimo...) |
| **REST API** | API completa para integrar Ciber-Shield en pipelines CI/CD o herramientas externas |
| **Dashboard Web** | Interfaz visual con gráficas de riesgo, listado de hosts y hallazgos |
| **Informes** | Generación de informes HTML/PDF profesionales listos para entregar al cliente |
| **CLI** | Interfaz de línea de comandos completa con output enriquecido (Rich) |

---

## 🏗️ Arquitectura

```
Ciber-Shield/
│
├── core/                   # Núcleo: config, BD, modelos, logger
│   ├── config.py           # Gestión de configuración (.env)
│   ├── database.py         # SQLAlchemy engine + sesiones
│   ├── models.py           # Modelos ORM (Scan, Host, Port, Vulnerability...)
│   └── logger.py           # Sistema de logging centralizado
│
├── scanner/                # Módulo de escaneo de red
│   ├── discovery.py        # Ping sweep / host discovery
│   ├── port_scanner.py     # TCP/UDP port scanning
│   ├── service_probe.py    # Detección de servicios y versiones
│   └── orchestrator.py     # Coordinación del pipeline de escaneo
│
├── vuln/                   # Motor de vulnerabilidades
│   ├── nvd_client.py       # Cliente de la NVD API v2.0
│   ├── correlator.py       # Correlación servicio → CVE
│   └── risk_scorer.py      # Puntuación de riesgo CVSS-based
│
├── detect/                 # Motor de reglas de detección
│   ├── rules.py            # Definición de reglas (YAML)
│   └── engine.py           # Motor de evaluación de reglas
│
├── report/                 # Generación de informes
│   ├── html_generator.py   # Informe HTML profesional
│   ├── pdf_generator.py    # Conversión a PDF
│   └── templates/          # Plantillas Jinja2 del informe
│
├── api/                    # REST API (Flask Blueprints)
│   ├── routes_scan.py      # /api/scans
│   ├── routes_host.py      # /api/hosts
│   └── routes_report.py    # /api/reports
│
├── web/                    # Dashboard web
│   ├── templates/          # HTML con Jinja2 + Bootstrap 5
│   └── static/             # CSS, JS, Chart.js
│
├── cli/                    # Interfaz de línea de comandos
│   └── commands.py         # Comandos Click + Rich
│
├── data/                   # Base de datos SQLite (auto-generada)
├── logs/                   # Logs de la aplicación
├── reports/                # Informes generados
│
├── requirements.txt
├── .env.example
└── app.py                  # Punto de entrada principal
```

---

## 🚀 Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/Constan4/Ciber-Shield.git
cd Ciber-Shield

# 2. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Configurar variables de entorno
cp .env.example .env
# Editar .env con tu API key de NVD (opcional pero recomendado)

# 5. Inicializar la base de datos
python3 app.py init-db

# 6a. Lanzar el dashboard web
python3 app.py web

# 6b. O usar la CLI directamente
python3 app.py scan --target 192.168.1.0/24 --name "Auditoría LAN"
```

---

## 🖥️ Uso — CLI

```bash
# Escaneo completo de una red
python3 app.py scan --target 192.168.1.0/24 --name "Red corporativa" --ports 1-1024

# Escaneo de un host específico con todos los puertos
python3 app.py scan --target 192.168.1.41 --name "Servidor web" --ports all

# Listar auditorías guardadas
python3 app.py list-scans

# Ver detalle de una auditoría
python3 app.py show-scan --id 1

# Generar informe HTML de una auditoría
python3 app.py report --scan-id 1 --format html

# Generar informe PDF
python3 app.py report --scan-id 1 --format pdf
```

---

## 🌐 Uso — Dashboard Web

```bash
python3 app.py web
# Abrir http://localhost:5000 en el navegador
```

El dashboard incluye:
- **Vista general:** resumen de auditorías, estadísticas y score de riesgo
- **Mapa de hosts:** todos los hosts descubiertos con su nivel de riesgo
- **Detalle de host:** puertos, servicios, CVEs y hallazgos de detección
- **Centro de informes:** generar y descargar informes
- **API Explorer:** documentación interactiva de la API REST

---

## 🔌 REST API

```bash
# Iniciar una nueva auditoría
POST /api/scans
{
  "name": "Auditoría red interna",
  "target": "192.168.1.0/24",
  "port_range": "1-1024"
}

# Obtener estado de una auditoría
GET /api/scans/{id}

# Listar hosts de una auditoría
GET /api/scans/{id}/hosts

# Obtener vulnerabilidades de un host
GET /api/hosts/{id}/vulnerabilities

# Generar informe
POST /api/reports
{ "scan_id": 1, "format": "html" }
```

---

## 🛠️ Stack tecnológico

| Capa | Tecnología |
|------|-----------|
| Backend | Python 3.10+, Flask 3.0 |
| ORM / BD | SQLAlchemy 2.0, SQLite (dev) / PostgreSQL (prod) |
| Frontend | Bootstrap 5, Chart.js, Jinja2 |
| CLI | Click, Rich |
| Informes | WeasyPrint, Jinja2 |
| APIs externas | NVD (NIST) para CVEs |
| Tests | pytest, pytest-flask |

---

## 📋 Roadmap

- [x] **1** — Core: configuración, base de datos, modelos
- [x] **2** — Scanner: discovery, port scan, service probe
- [x] **3** — CVE Engine: NVD API, correlación, risk score
- [x] **4** — Detection Rules + REST API
- [x] **5** — Dashboard web (Bootstrap + Chart.js)
- [ ] **6** — Generador de informes HTML/PDF
- [ ] **7** — CLI completa + tests + documentación

---

## ⚠️ Aviso Legal

> Esta herramienta es para uso exclusivo en auditorías de seguridad **con autorización expresa**.
> El escaneo de redes sin permiso puede ser ilegal. Úsala responsablemente.

---

*Desarrollado por [Constan4](https://github.com/Constan4)*
