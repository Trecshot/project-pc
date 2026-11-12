<div align="center">

# 🛡️ DataCleaner

**Auditoría Forense Binaria, Deduplicación Multi-Stage y Mitigación Transaccional bajo Política de Cero Pérdida de Datos**

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.15-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-93%2F93%20Passed%20(100%25)-2EA043?style=for-the-badge&logo=pytest&logoColor=white)](tests/)
[![Security](https://img.shields.io/badge/Security-NIST%20SSDF%20%7C%20Zero--Trust-8957E5?style=for-the-badge&logo=shield&logoColor=white)](SECURITY.md)
[![UI](https://img.shields.io/badge/UI-Fluent%20Design%20(Win11)-0078D4?style=for-the-badge&logo=windows11&logoColor=white)](datacleaner/gui.py)
[![Compiler](https://img.shields.io/badge/Build-Nuitka%20AOT%20C-F39C12?style=for-the-badge&logo=c&logoColor=white)](build_executable.py)
[![License](https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge)](LICENSE)

[Arquitectura](#arquitectura) • [Seguridad Forense](#seguridad-forense) • [Modos de Mitigación](#modos-de-mitigación) • [Instalación](#instalación) • [Guía CLI](#guía-cli) • [Compilación AOT](#compilación-aot)

</div>

---

## 📋 Descripción General

**DataCleaner** es una suite de escritorio (interfaz moderna **Fluent Design Windows 11** accesible WCAG 2.1 AA) y de línea de comandos (**CLI** enriquecida con *Rich*) diseñada para auditar, detectar y mitigar archivos duplicados bit a bit sin comprometer la integridad del almacenamiento ni del sistema operativo.

A diferencia de los limpiadores tradicionales, DataCleaner opera bajo un modelo **Dry-Run obligatorio**, incorpora **inspección forense de cabeceras binarias (Magic Numbers)**, previene condiciones de carrera a nivel de kernel (**Anti-TOCTOU**) y mantiene una bitácora histórica inmutable (**Tamper-Evident Hash-Chain** con HMAC-SHA256).

---

## <a id="arquitectura"></a>⚡ Arquitectura y Pipeline Multi-Stage

Para saturar el bus de almacenamiento (NVMe/SSD) minimizando operaciones de lectura en disco, el motor de escaneo (`scanner.py` + `hasher.py`) ejecuta un embudo progresivo en tres fases:

```mermaid
flowchart LR
    A[📂 Escaneo de Directorio] --> B{Fase 1: O(1) RAM<br/>st_size + BloomFilter}
    B -->|Tamaño único| C[🗑️ Descartado sin I/O]
    B -->|Colisión de tamaño| D{Fase 2: O(k) Fast-Hash<br/>Primer + Último 64 KB<br/>XXH3 / BLAKE2b}
    D -->|Extremos distintos| C
    D -->|Colisión de extremos| E{Fase 3: O(n) SHA-256<br/>Chunks 64 KB en<br/>ThreadPoolExecutor}
    E -->|Hash único| C
    E -->|SHA-256 Idéntico| F[🔍 Análisis Forense<br/>Magic Numbers + OOXML]
    F --> G[🛡️ Plan de Mitigación<br/>Dry-Run / Cuarentena / CoW]
```

| Etapa | Complejidad | Mecanismo Técnico | Impacto en Rendimiento |
| :--- | :---: | :--- | :--- |
| **Fase 1: Agrupación en RAM** | $\mathcal{O}(1)$ | Tablas hash nativas en C por `st_size` + soporte cooperativo de `BloomFilter` (Kirsch-Mitzenmacher) e ignorado de hardlinks existentes (`st_nlink > 1`). | Descarta instantáneamente archivos únicos sin leer contenido. |
| **Fase 2: Fast-Hash de Extremos** | $\mathcal{O}(k)$ | Lectura parcial de los primeros y últimos 64 KB mediante `xxhash` (XXH3 128-bit) / `BLAKE2b` + consulta previa en caché SQLite $\mathcal{O}(1)$. | Elimina >95% de falsas colisiones de tamaño con mínimo I/O. |
| **Fase 3: SHA-256 Criptográfico** | $\mathcal{O}(n)$ | Hashing completo por bloques de 64 KB ejecutado en hilos nativos (`ThreadPoolExecutor`) liberando el GIL en C. | Garantía matemática de identidad bit a bit (cero colisiones). |

---

## <a id="seguridad-forense"></a>🛡️ Seguridad Forense y Hardening

DataCleaner implementa controles estrictos alineados con **NIST SSDF (SP 800-218)**, **OWASP** y **CWE-434**:

* **Inspección Forense de Cabeceras (`magic.py`):** Valida los primeros bytes reales de cada duplicado contra una tabla determinista de firmas binarias (`%PDF`, `MZ`, `\x7fELF`, PNG, JPEG, SQLite, LNK, shebangs `#!`, bytecode `.pyc` y scripts HTML/HTA).
* **Inspección Profunda de Contenedores OOXML y Anti-Zip Bomb:** Analiza en memoria paquetes `.docx`, `.xlsx` y `.pptx` verificando `[Content_Types].xml`, bloqueando archivos con más de 10,000 entradas (prevención DoS) y alertando si encapsulan ejecutables ocultos (`SUSPICIOUS_ARCHIVE_WRAPPER`).
* **Defensa contra Suplantación RTLO (`\u202E`):** Detecta y penaliza severamente (-10,000 pts) nombres de archivo que utilizan caracteres Unicode Right-to-Left Override para disfrazar ejecutables como documentos.
* **Blindaje Anti-TOCTOU a Nivel Kernel (`quarantine.py`):** Antes de mover, enlazar o borrar, abre descriptores de archivo (`os.open`) con exclusión y bloqueo no bloqueante (`msvcrt.locking` / `fcntl.flock`), validando `st_size` y `st_mtime` vía `os.fstat(fd)` para abortar si el archivo mutó tras el escaneo.
* **Auditoría Inmutable Tamper-Evident (`history.py`):** Base de datos SQLite (`.datacleaner.sqlite`) con `PRAGMA journal_mode = WAL`, `PRAGMA secure_delete = ON`, permisos DACL/chmod 0600 restringidos al propietario y encadenamiento criptográfico Append-Only (`prev_hash` → `entry_hash` firmado con HMAC-SHA256).
* **Aislamiento de Rutas Críticas (`security.py`):** Lista negra estricta (`SYSTEM_BLACKLIST`) que bloquea particiones raíz (`C:\`, `/`), Windows, System32, Program Files, AppData, `.git`, `node_modules` y entornos virtuales.

---

## <a id="modos-de-mitigación"></a>🔄 4 Modos de Mitigación Transaccional

1. **Cuarentena Reversible (Soft-Delete — Por defecto):** Traslada los duplicados a `_quarantine_YYYYMMDD_HHMMSS/` preservando su jerarquía relativa, generando `manifest.json` y su firma digital `manifest.json.sig` (HMAC-SHA256). La restauración verifica la firma criptográfica y bloquea intentos de Path Traversal.
2. **Deduplicación CoW / Hardlinks (Block Cloning):** Pipeline transparente en dos etapas: intenta clonación de bloques Copy-on-Write nativa a nivel de kernel (ReFS/DevDrive `FSCTL_DUPLICATE_EXTENTS_TO_FILE` en Windows, `FICLONE` en Linux Btrfs/XFS, `clonefile` en macOS APFS) con fallback automático a enlaces físicos (`os.link`) y respaldo transaccional (`.dc_hl_bak`). Libera el 100% del espacio manteniendo todas las rutas intactas.
3. **Papelera de Reciclaje:** Envía copias redundantes a la Papelera del sistema mediante `send2trash` (aborta con `RuntimeError` si la librería no está disponible para evitar borrados accidentales).
4. **Eliminación Permanente:** Borrado definitivo en disco (`unlink`) tras confirmación explícita.

### Reglas Heurísticas de Conservación (KeepRule)

Al evaluar un grupo de duplicados, DataCleaner puntúa cada ruta penalizando carpetas provisionales (`Downloads`, `Descargas`, `temp`, `tmp`, `cache`, `backup`, `copia`) y aplica la regla seleccionada:

* `deepest_then_newest` **(Recomendado):** Conserva la copia en la ruta más estructurada/profunda y reciente.
* `deepest_then_oldest:` Conserva la copia más estructurada y antigua.
* `shallowest_then_newest:` Conserva la copia más cercana al directorio raíz.
* `newest` / `oldest:` Conserva estrictamente por fecha de modificación (`st_mtime`).

---

## <a id="instalación"></a>🚀 Instalación y Ejecución

### Requisitos
* **Python:** 3.10 o superior (totalmente compatible con Python 3.13 y 3.15 / Tcl 9).
* **Sistema Operativo:** Windows 10/11 (con soporte nativo para barra de título inmersiva DWM y tema Fluent Design) o Linux/macOS.

### Configuración

```bash
# 1. Clonar el repositorio
git clone https://github.com/Trecshot/project-pc.git
cd project-pc

# 2. Crear y activar entorno virtual
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt
```

### Iniciar Interfaz Gráfica (GUI)

```bash
# Ejecución directa (inicia GUI por defecto sin argumentos)
python main.py

# O especificando una carpeta inicial
python main.py gui "C:\Users\Usuario\Downloads"
```

> [!TIP]
> **En Windows:** Haz doble clic en `iniciar.bat` para lanzar la aplicación silenciosamente mediante `pythonw.exe` sin ventana de consola.

---

## ⌨️ Atajos de Teclado en la GUI

| Atajo | Acción | Atajo | Acción |
| :---: | :--- | :---: | :--- |
| <kbd>F5</kbd> | Iniciar simulación (Dry-Run) | <kbd>Ctrl</kbd> + <kbd>G</kbd> | Abrir Gestor de Cuarentena / Restaurar |
| <kbd>Ctrl</kbd> + <kbd>O</kbd> | Seleccionar carpeta a auditar | <kbd>Ctrl</kbd> + <kbd>E</kbd> | Exportar reporte de auditoría a JSON |
| <kbd>Ctrl</kbd> + <kbd>F</kbd> | Enfocar barra de filtrado en vivo | <kbd>Ctrl</kbd> + <kbd>T</kbd> | Alternar Tema Oscuro / Claro (Fluent UI) |

---

## <a id="guía-cli"></a>💻 Referencia de Línea de Comandos (CLI)

DataCleaner cuenta con una CLI completa impulsada por *Rich* y automatizable mediante el Programador de Tareas de Windows (`schtasks.exe`):

```bash
# 1. Auditoría Dry-Run (solo lectura, exportando reporte JSON y ofreciendo cuarentena al final)
python main.py scan "C:\Ruta\Objetivo" --keep-rule deepest_then_newest --workers 4 --json-out reporte.json -i

# 2. Aislar duplicados en cuarentena (modo no interactivo con -y)
python main.py quarantine "C:\Ruta\Objetivo" --keep-rule deepest_then_newest -y

# 3. Enviar duplicados directamente a la Papelera de Reciclaje
python main.py quarantine "C:\Ruta\Objetivo" --direct --trash -y

# 4. Restaurar archivos desde un manifiesto firmado criptográficamente
python main.py restore "C:\Ruta\Objetivo\_quarantine_20261112_010000\manifest.json"

# 5. Purgar definitivamente todas las sesiones de cuarentena de un directorio
python main.py purge "C:\Ruta\Objetivo" -y
```

---

## <a id="compilación-aot"></a>⚙️ Compilación AOT a Binario Nativo (.exe)

El script `build_executable.py` compila el proyecto a código C nativo mediante **Nuitka** generando un ejecutable autónomo sin consola en segundo plano:

```bash
# Compilar binario + limpieza previa + generación automática de SBOM (CycloneDX)
python build_executable.py

# Limpiar únicamente cachés residuales (.pyc, __pycache__, .tcl_bundle, SQLite local)
python build_executable.py --clean
```

* **Soporte Python 3.15 / Tcl 9:** Extrae automáticamente las librerías embebidas en `//zipfs:/lib/` hacia `.tcl_bundle/` antes de invocar Nuitka.
* **Supply Chain Security (NIST SSDF PS.3.2):** Genera `dist/datacleaner_sbom.json` en formato CycloneDX.
* **Firma Digital Authenticode:** Si defines `CODESIGN_THUMBPRINT`, firma el ejecutable resultante vía `signtool.exe` con timestamp SHA-256.

### Variables de Entorno Opcionales

| Variable | Propósito |
| :--- | :--- |
| `DATACLEANER_DB_PATH` | Ruta personalizada para la base de datos SQLite de auditoría y caché. |
| `DATACLEANER_AUDIT_KEY` | Clave secreta personalizada de 256 bits para firmas HMAC-SHA256. |
| `CODESIGN_THUMBPRINT` | Huella digital SHA-1 del certificado para firma Authenticode en compilación. |

---

## 📁 Estructura del Repositorio

```text
project-pc/
├── .github/workflows/       # Pipelines CI/CD y auditoría de seguridad (pip-audit, bandit, SBOM)
├── datacleaner/
│   ├── assets/              # Manifiestos y recursos visuales de la aplicación
│   ├── bloom.py             # Filtro de Bloom probabilístico en RAM (Kirsch-Mitzenmacher)
│   ├── cli.py               # Interfaz de línea de comandos con tablas y barras Rich
│   ├── gui.py               # Interfaz gráfica Fluent Design (Sun Valley TTK / Matplotlib)
│   ├── hasher.py            # Hashing escalonado XXH3 / BLAKE2b / SHA-256 y control de workers
│   ├── history.py           # Persistencia SQLite WAL, caché O(1) y Hash-Chain HMAC
│   ├── magic.py             # Auditoría forense de Magic Numbers, OOXML y detección RTLO
│   ├── quarantine.py        # Cuarentena firmada, Reflinks CoW, Hardlinks y blindaje TOCTOU
│   ├── reporter.py          # Planificador de auditoría Dry-Run y serialización JSON
│   ├── rules.py             # Motor heurístico de conservación y tokenización de rutas
│   ├── scanner.py           # Escáner concurrente Multi-Stage y protección de recursos dev
│   ├── scheduler.py         # Integración con Windows Task Scheduler (schtasks.exe)
│   └── security.py          # Blacklist del SO, validación de rutas y gestión de claves HMAC
├── tests/                   # Suite de 93 pruebas (unitarias, fuzzing, hardening, TOCTOU)
├── build_executable.py      # Compilador AOT Nuitka + generador SBOM + firma Authenticode
├── iniciar.bat              # Lanzador silencioso de un clic en Windows
├── main.py                  # Punto de entrada unificado (GUI / CLI)
├── pyproject.toml           # Metadatos del paquete y configuración Ruff / Pytest
├── requirements.txt         # Dependencias de producción y desarrollo
└── SECURITY.md              # Política de Divulgación Coordinada (CVD) y gobernanza
```

---

## 🧪 Pruebas y Aseguramiento de Calidad

Ejecuta la suite completa de 93 pruebas automatizadas:

```bash
pytest tests/ -v
```

La cobertura incluye:
* **Simulación TOCTOU (`test_audit_fixes.py`):** Mutación en caliente de archivos entre escaneo y mitigación.
* **Fuzzing Forense (`test_fuzzing_resilience.py`):** Cabeceras corruptas (0–16 bytes), secuencias ANSI, homoglyphs Unicode, rutas >260 caracteres (`\\?\`), Zip Bombs y scripts camuflados.
* **Hardening (`test_hardening.py`):** Prevención de colisiones en cuarentena, enlaces simbólicos/junctions y aislamiento de caché SQLite.

---

## 📄 Licencia

Distribuido bajo la licencia MIT. Consulta [LICENSE](LICENSE) y [SECURITY.md](SECURITY.md) para políticas de seguridad y gobernanza.
