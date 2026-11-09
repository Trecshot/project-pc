# 🛡️ DataCleaner

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.15-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-83%2F83%20Passed%20(100%25)-success?logo=pytest&logoColor=white)](tests/)
[![Security](https://img.shields.io/badge/Security-NIST%20SSDF%20%7C%20Zero--Trust-blueviolet?logo=shield&logoColor=white)](SECURITY.md)
[![UI](https://img.shields.io/badge/UI-Fluent%20Design%20(Windows%2011)-0078D4?logo=windows11&logoColor=white)](datacleaner/gui.py)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Auditoría Forense Binaria, Deduplicación de Archivos y Mitigación bajo Política de Cero Pérdida de Datos**

</div>

---

**DataCleaner** es una herramienta de escritorio (interfaz gráfica moderna Fluent Design Windows 11) y de línea de comandos (CLI) diseñada para auditar, organizar y deduplicar archivos bit a bit de forma segura, garantizando la integridad de tus datos y del sistema operativo.

---

## 🚀 Capacidades Principales

### 1. Pipeline de Detección Escalonada (Multi-Stage Hashing)
* **Fase 1 — Agrupación $O(1)$ en RAM:** Agrupa instantáneamente por tamaño de archivo (`st_size`) con tablas hash nativas de alto rendimiento, descartando elementos únicos sin realizar lecturas previas en disco. Incluye soporte cooperativo de `BloomFilter` probabilístico (Kirsch-Mitzenmacher) para contención estricta de memoria en volúmenes masivos.
* **Fase 2 — Fast-Hash de Extremos (128 KB):** Lee únicamente los primeros y últimos 64 KB de los archivos candidatos mediante streaming ultra-rápido en RAM (XXH3 / BLAKE / SHA-256 + seek) para descartar falsas colisiones de tamaño con mínimo coste de E/S (NIST SP 800-131A / FIPS 140-3).
* **Fase 3 — SHA-256 Criptográfico Bit a Bit:** Calcula el hash criptográfico por bloques de 64 KB en hilos nativos de trabajo (`ThreadPoolExecutor`) liberando el GIL en C, garantizando coincidencia unívoca al 100%.

### 2. Seguridad Operativa y Cero Pérdida de Datos
* **Blindaje Anti-TOCTOU a Nivel Kernel:** Inspección atómica sobre descriptores de archivos (`os.fstat(fd)`) con exclusión y bloqueo no bloqueante (`msvcrt.locking` / `fcntl.flock`), capturando metadatos validados (`verified_stat`) para evitar condiciones de carrera antes de cualquier traslado o eliminación.
* **Protección de Rutas Críticas:** Bloqueo estricto contra escaneos o modificaciones accidentales en directorios esenciales del sistema (`Windows`, `Program Files`, `System32`, `AppData` y particiones raíz).
* **Análisis Forense Determinista (Magic Numbers / CWE-434):** Inspecciona las cabeceras binarias reales (PDF, PNG, JPG, ZIP, ejecutables MZ/ELF, scripts camuflados y ofuscación visual RTLO `\u202E`).

### 3. 4 Modos de Mitigación Transaccional
* **Cuarentena Reversible (Soft-Delete):** Traslada los duplicados a una carpeta de aislamiento con un archivo `manifest.json` y firma digital `manifest.json.sig` (HMAC-SHA256), permitiendo restaurarlos a su ubicación original en un solo clic.
* **Deduplicación por Hardlinks (`os.link`):** Libera el 100% del espacio redundante haciendo que múltiples rutas apunten al mismo sector físico en disco (NTFS/ext4) mediante un proceso transaccional con respaldo temporal (`.dc_hl_bak`).
* **Papelera de Reciclaje:** Envía los duplicados a la Papelera de Windows mediante `send2trash` con validación previa de librerías.
* **Eliminación Permanente:** Borrado definitivo del disco previa confirmación explícita.

### 4. Caché Inteligente y Auditoría Tamper-Evident
* Reutiliza hashes calculados previamente mediante una base de datos local SQLite (`.datacleaner.sqlite`) en modo WAL y `PRAGMA secure_delete = ON`.
* Encadenamiento criptográfico Append-Only (`prev_hash` ➔ `entry_hash` con HMAC-SHA256) para certificar matemáticamente la inmutabilidad de la bitácora histórica de operaciones.

---

## 🛠️ Instalación y Requisitos

### Requisitos del Sistema
* **Python:** 3.10 o superior (compatible con Python 3.15 y Tcl 9).
* **Sistema Operativo:** Windows 10/11 (recomendado para Fluent Design y temas DWM) o sistemas Linux/macOS.

### Instalación Rápida
```bash
# Clonar el repositorio
git clone https://github.com/Trecshot/project-pc.git
cd project-pc

# Crear y activar entorno virtual
python -m venv .venv

# En Windows:
.venv\Scripts\activate

# En Linux/macOS:
source .venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

---

## 💻 Uso

### Interfaz Gráfica (GUI)
Puedes iniciar la aplicación con interfaz gráfica ejecutando:
```bash
python main.py --gui
```
*(O haciendo doble clic directamente sobre `iniciar.bat` en Windows).*

### Línea de Comandos (CLI)
```bash
# 1. Simulación y auditoría previa (Dry-Run seguro sin modificar archivos)
python main.py scan "C:\Ruta\A\Escanear"

# 2. Aislamiento interactivo en cuarentena
python main.py quarantine "C:\Ruta\A\Escanear" --keep-rule deepest_then_newest

# 3. Restaurar archivos desde un manifiesto de cuarentena
python main.py restore "C:\Ruta\_quarantine_YYYYMMDD_HHMMSS\manifest.json"

# 4. Purgar definitivamente sesiones de cuarentena antiguas
python main.py purge "C:\Ruta\A\Escanear"
```

---

## 📦 Compilación AOT a Binario Nativo (.exe)

El proyecto incluye un script de compilación Ahead-of-Time (AOT) que traduce el código Python a C y genera un ejecutable nativo mediante Nuitka:

```bash
# Compilar binario con limpieza previa y generación de SBOM
python build_executable.py

# Solo limpiar cachés locales y artefactos temporales
python build_executable.py --clean
```

### Características del proceso de compilación:
* **Extracción automática de librerías Tcl/Tk:** Extrae recursos desde el sistema virtual `zipfs` (compatibilidad total con Python 3.15+).
* **Limpieza preventiva:** Purga archivos `.pyc`, carpetas `__pycache__` y bases SQLite locales.
* **Generación automatizada de SBOM:** Crea inventario CycloneDX JSON según directrices NIST SSDF PS.3.2.
* **Firma digital opcional Authenticode:** Firma binarios con `signtool.exe` si la variable `CODESIGN_THUMBPRINT` está presente.

---

## 📁 Estructura del Proyecto

```text
datacleaner/
├── scanner.py          # Pipeline de detección Multi-Stage (O(1) -> O(k) -> O(n)) y concurrencia.
├── hasher.py           # Algoritmos de lectura parcial (XXH3/BLAKE) y SHA-256 criptográfico en C.
├── bloom.py            # Filtro de Bloom probabilístico en RAM (Kirsch-Mitzenmacher).
├── security.py         # Lista negra del SO, validación estricta de rutas y gestión de claves HMAC.
├── quarantine.py       # Cuarentena reversible, hardlinks transaccionales y blindaje anti-TOCTOU.
├── reporter.py         # Construcción del plan de auditoría previa y serialización JSON.
├── rules.py            # Reglas heurísticas de permanencia (scoring de rutas estructuradas y fechas).
├── history.py          # Persistencia transaccional SQLite, Stateful Cache y series temporales.
├── magic.py            # Auditoría forense determinista de cabeceras binarias (Magic Numbers).
├── scheduler.py        # Integración con el Programador de Tareas de Windows (schtasks.exe).
├── gui.py              # Interfaz gráfica moderna Fluent Design (Sun Valley TTK / Windows 11).
└── cli.py              # Interfaz de consola interactiva con tablas Rich y barras de progreso.

main.py                 # Punto de entrada unificado para iniciar la aplicación (CLI o GUI).
build_executable.py     # Script de compilación AOT a C nativo con Nuitka.
iniciar.bat             # Lanzador rápido de un clic para Windows.
```

---

## 🧪 Pruebas y Aseguramiento de Calidad

Para ejecutar la batería completa de pruebas unitarias, de concurrencia y resiliencia forense:

```bash
pytest tests/ -v
```

### La suite valida:
* **Resiliencia Anti-TOCTOU:** Simulación de mutación en caliente durante mitigación.
* **Detección Forense:** Fuzzing de cabeceras (0 a 16 bytes), suplantación RTLO Unicode y contenedores OOXML anómalos.
* **Concurrencia Segura:** Control de descriptores de archivos del SO (`get_safe_worker_count`) y consultas $O(1)$ en SQLite.
* **Inmutabilidad Criptográfica:** Verificación de firmas HMAC en manifiestos y cadenas de auditoría append-only.
