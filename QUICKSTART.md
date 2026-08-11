# 🚀 QUICKSTART — Cómo ejecutar Ciber-Shield

Guía completa para poner en marcha Ciber-Shield en tu laboratorio y
realizar una auditoría real sobre tu red local.

---

## Prerequisitos

| Elemento | Detalle |
|----------|---------|
| **SO atacante** | Kali Linux 2025.x (o cualquier Linux con Python 3.10+) |
| **Python** | 3.10 o superior |
| **Red** | Acceso a la red local que quieres auditar |
| **Autorización** | Solo sobre sistemas **de tu propiedad** o con permiso expreso |

---

## 1. Instalación

```bash
# Clonar el repositorio
git clone https://github.com/Constan4/Ciber-Shield.git
cd Ciber-Shield

# (Recomendado) Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Verificar que todo está OK
python3 app.py status
```

---

## 2. Configuración inicial

```bash
# Copiar la plantilla de variables de entorno
cp .env.example .env

# Editar .env (opcional pero recomendado)
nano .env
```

**Variables clave en `.env`:**

```ini
# API key gratuita de NVD para más velocidad en correlación CVEs
# Obtener en: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=tu_api_key_aqui

# Timeout por host (subir a 2.0 si la red es lenta)
SCANNER_TIMEOUT=1.0

# Hilos concurrentes (bajar a 50 si hay problemas de red)
SCANNER_MAX_THREADS=150
```

```bash
# Inicializar la base de datos
python3 app.py init-db

# Verificar el estado del sistema
python3 app.py status
```

---

## 3. Ejecutar una auditoría

### Opción A — Desde la CLI (recomendado para aprender)

```bash
# ── Descubrir hosts en tu red ──────────────────────────────────
python3 app.py scan \
    --target 192.168.1.0/24 \
    --ports common \
    --name "Mi primer scan"

# ── Opciones importantes ───────────────────────────────────────
# --target   IP individual, rango CIDR o hostname
# --ports    common | 1-1024 | all | 22,80,443,3389
# --timeout  Tiempo de espera por host (default: 1.0)
# --no-vuln  Saltar análisis de CVEs (más rápido)
# --no-detect Saltar el motor de reglas
```

**Ejemplos según tu laboratorio:**

```bash
# Escanear toda la red local
python3 app.py scan --target 192.168.1.0/24 --ports common

# Escanear solo el equipo Windows objetivo
python3 app.py scan --target 192.168.1.41 --ports 1-1024 --name "Windows 11 ASUS"

# Escaneo rápido de puertos más habituales
python3 app.py scan --target 192.168.1.41 --ports common --timeout 0.5

# Escaneo completo de todos los puertos (más lento)
python3 app.py scan --target 192.168.1.41 --ports all
```

### Opción B — Desde el dashboard web

```bash
# Lanzar el servidor web
python3 app.py web

# Abrir en el navegador: http://localhost:5000
# → Ir a "Nueva auditoría" → rellenar el formulario → Lanzar
```

---

## 4. Ver resultados

```bash
# Listar todas las auditorías guardadas
python3 app.py list-scans

# Ver detalle completo de la auditoría ID 1
python3 app.py show-scan --id 1
```

**Ejemplo de salida esperada:**

```
  🛡️  #1 — Mi primer scan
  ─────────────────────────────────────────────────────────────
  Target  : 192.168.1.0/24  |  Puertos: common
  Estado  : COMPLETED
  Hosts   : 7  Puertos: 23  CVEs: 12  Hallazgos: 5
  Riesgo  : 8.5/10  (HIGH)

  ┌── 192.168.1.41  (DESKTOP-01O917C)
  │   OS     : Windows 11 21H2
  │   Riesgo : 8.5/10
  │     135/tcp  msrpc
  │     139/tcp  netbios-ssn  ⚠
  │     445/tcp  smb ⚠
  │              [CRITICAL] CVE-2017-0144  CVSS:9.3
  │   [RULE-004] SMB (445) expuesto en la red
  │   [RULE-003] NetBIOS-SSN expuesto (posible SMBv1)
```

---

## 5. Análisis de CVEs (si aún no se ejecutó)

```bash
# Ejecutar correlación CVE sobre un scan ya realizado
python3 app.py analyze --id 1

# Ejecutar solo el motor de detección de reglas
python3 app.py detect --id 1
```

---

## 6. Generar el informe

```bash
# Informe HTML (siempre disponible)
python3 app.py report --id 1 --format html

# Informe PDF (requiere WeasyPrint)
pip install WeasyPrint
# Ubuntu/Kali: sudo apt install libcairo2-dev libpango1.0-dev
python3 app.py report --id 1 --format pdf

# Abrir el informe HTML en el navegador
xdg-open reports/report_1_*.html
```

---

## 7. API REST (para integraciones)

```bash
# Lanzar el servidor web
python3 app.py web

# En otra terminal:

# Estado de la API
curl http://localhost:5000/api/health | python3 -m json.tool

# Listar auditorías
curl http://localhost:5000/api/scans | python3 -m json.tool

# Crear y lanzar un nuevo scan por API
curl -X POST http://localhost:5000/api/scans \
     -H "Content-Type: application/json" \
     -d '{"name":"API test","target":"192.168.1.41","port_range":"common"}' \
     | python3 -m json.tool

# Ver detalle de la auditoría 1
curl http://localhost:5000/api/scans/1 | python3 -m json.tool

# Ver hosts del scan 1
curl http://localhost:5000/api/scans/1/hosts | python3 -m json.tool

# Ver resumen de riesgo
curl http://localhost:5000/api/scans/1/summary | python3 -m json.tool
```

---

## 8. Ejecutar los tests

```bash
# Todos los tests
make test

# Solo tests rápidos (sin API, sin BD compleja)
make test-fast

# Tests con más detalle
pytest tests/ -v --tb=long

# Un test específico
pytest tests/test_rules.py::TestRule001Telnet -v
```

---

## Flujo completo de práctica (para el laboratorio del TFG)

```bash
# 1. En Kali Linux — Preparar el entorno
cd ~/Ciber-Shield
source venv/bin/activate
python3 app.py init-db

# 2. En el equipo Windows objetivo — (para la fase de ataque del TFG)
#    Desactivar temporalmente el Firewall y el Antivirus en tiempo real
#    (solo para la demostración, en producción NO hacerlo)

# 3. Escaneo completo del equipo Windows
python3 app.py scan \
    --target 192.168.1.41 \
    --ports 1-1024 \
    --name "Auditoría Windows 11 ASUS"

# 4. Ver resultados
python3 app.py show-scan --id 1

# 5. Lanzar el dashboard para ver todo visualmente
python3 app.py web &
xdg-open http://localhost:5000

# 6. Generar el informe profesional
python3 app.py report --id 1 --format html
xdg-open reports/report_1_*.html

# 7. (Hardening) Volver al equipo Windows y activar el Firewall
#    python3 app.py scan --target 192.168.1.41 --name "Post-hardening"
#    Comparar los risk scores antes y después
```

---

## Comandos de referencia rápida

```
python3 app.py init-db                       Inicializar BD
python3 app.py status                        Estado del sistema
python3 app.py scan --target IP              Escaneo completo
python3 app.py analyze --id N               Análisis CVE de un scan
python3 app.py detect --id N                Motor de detección
python3 app.py list-scans                   Listar auditorías
python3 app.py show-scan --id N             Detalle de una auditoría
python3 app.py report --id N --format html  Generar informe
python3 app.py web                          Dashboard web

make install   pip install -r requirements.txt
make init      init-db
make scan      scan con TARGET y PORTS configurables
make web       lanzar dashboard
make test      pytest tests/
make clean     borrar BD, logs y reports
```

---

## Resolución de problemas frecuentes

| Problema | Solución |
|----------|---------|
| `ModuleNotFoundError: flask` | `pip install -r requirements.txt` |
| Scan no encuentra hosts | El firewall bloquea ICMP — probar con `--target IP_exacta` |
| CVEs no se cargan | La NVD API tiene rate-limit — esperar 30s o añadir API key en `.env` |
| `WeasyPrint` error | `sudo apt install libcairo2-dev libpango1.0-dev` |
| Puerto 5000 ocupado | `python3 app.py web --port 5001` |
| BD corrupta | `python3 app.py init-db --reset` |

---

*Ciber-Shield v1.0 — github.com/Constan4/Ciber-Shield*
