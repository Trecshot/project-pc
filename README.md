# 🛡️ DataCleaner

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.15-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-83%2F83%20Passed%20(100%25)-success?logo=pytest&logoColor=white)](tests/)
[![Security](https://img.shields.io/badge/Security-NIST%20SSDF%20%7C%20Zero--Trust-blueviolet?logo=shield&logoColor=white)](SECURITY.md)
[![Design](https://img.shields.io/badge/UI-Fluent%20Design%20(Sun%20Valley)-0078D4?logo=windows11&logoColor=white)](datacleaner/gui.py)
[![Architecture](https://img.shields.io/badge/Engine-Multi--Stage%20Hashing%20(O(1)%20%E2%86%92%20O(n))-orange)](#-arquitectura-del-pipeline-multi-stage)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Auditoría Inteligente, Forense Binaria y Deduplicación Bit a Bit bajo Política de Cero Pérdida de Datos**

[Descripción](#-descripción-general) •
[Arquitectura](#-arquitectura-del-pipeline-multi-stage) •
[Inicio Rápido](#-inicio-rápido) •
[Interfaz Gráfica](#-interfaz-gráfica-moderna) •
[Línea de Comandos](#-modo-línea-de-comandos-cli) •
[Modos de Limpieza](#-los-4-modos-de-mitigación) •
[Seguridad y Forense](#-seguridad-y-análisis-forense) •
[Compilación](#-compilación-nativa-aot-con-nuitka)

</div>

---

## 📖 Descripción General

**DataCleaner** es una suite de alto rendimiento de escritorio (GUI con Fluent Design de Windows 11) y línea de comandos (CLI) diseñada para auditar, organizar y deduplicar archivos con precisión criptográfica de $100\%$. 

A diferencia de los limpiadores convencionales, DataCleaner opera bajo una estricta **Política de Cero Pérdida de Datos**:
- **Cero falsos positivos:** Hashing escalonado bit a bit (SHA-256 en C liberando el GIL).
- **Blindaje anti-TOCTOU:** Bloqueo y verificación atómica de descriptores a nivel de Kernel antes de cualquier acción.
- **Cuarentena 100% reversible:** Manifiestos firmados criptográficamente mediante HMAC-SHA256 (NIST SSDF PO.4).
- **Deduplicación transparente:** Posibilidad de consolidar duplicados mediante **Hardlinks** a nivel de sistema operativo (`os.link`) sin mover archivos ni romper rutas de desarrollo.

---

## ⚡ Arquitectura del Pipeline Multi-Stage

DataCleaner implementa un pipeline de evaluación escalonado $O(1) \to O(k) \to O(n)$ que descarta el $99\%$ de los archivos antes de tocar el disco, evitando la saturación de E/S:

```mermaid
flowchart TD
    A["📂 Directorio Objetivo"] --> B["Fase 1: Recorrido O(1) en RAM<br/>Agrupación por st_size y Filtro de Hardlinks (st_nlink > 1)"]
    
    B -->|Tamaño Único| C["🟢 Descartado en RAM (Sin tocar disco)"]
    B -->|Tamaño Colisionante| D["Fase 2: Fast-Hash O(k)<br/>Lectura Parcial Streaming 128 KB (XXH3 / BLAKE / SHA-256)"]
    
    D -->|Extremos Distintos| E["🟢 Falsa Colisión Descartada"]
    D -->|Caché SQLite O(1)| F["⚡ Reutilización Inmediata de Hash (Stateful Cache)"]
    D -->|Extremos Idénticos| G["Fase 3: SHA-256 Criptográfico O(n)<br/>Lectura Completa por Bloques en C (GIL Liberado)"]
    
    G -->|Hash Único| H["🟢 Descarte Definitivo"]
    G -->|Hash Colisionante Bit a Bit| I["🔍 Análisis Forense (Magic Numbers)<br/>Detección de Extensiones Falsas y Amenazas (CWE-434)"]
    
    I --> J["📋 Construcción del Plan de Auditoría<br/>Reglas Heurísticas: Rutas Limpias, Profundidad y Fechas"]
    
    J --> K{"Acción de Mitigación Seleccionada"}
    K -->|Reversible| L["📦 Cuarentena Soft-Delete (Firmada con HMAC)"]
    K -->|Espacio Cero| M["🔗 Hardlinks a Nivel de SO (os.link)"]
    K -->|Recuperable| N["🗑️ Papelera de Reciclaje (Send2Trash)"]
    K -->|Irreversible| O["⚠️ Eliminación Permanente (Kernel Lock Anti-TOCTOU)"]
```

---

## 🚀 Inicio Rápido

### Requisitos del Sistema
* **Sistema Operativo:** Windows 10/11 (recomendado), Linux o macOS.
* **Python:** 3.10 o superior (compatible con Python 3.15).

### 1. Instalación de Dependencias
Clona el repositorio e instala los paquetes necesarios:

```bash
git clone https://github.com/tu-usuario/project-pc.git
cd project-pc
pip install -r requirements.txt
```

### 2. Lanzar la Aplicación

#### En Windows (Un Clic):
Haz doble clic sobre el archivo ejecutable por lotes:
* [**`iniciar.bat`**](file:///d:/Desarrollo/codigo/project-pc-main/iniciar.bat)

#### Mediante Consola:
```bash
# Iniciar Interfaz Gráfica (GUI Fluent Design)
python main.py

# O explícitamente:
python main.py gui
```

---

## 🖥️ Interfaz Gráfica Moderna

Construida con la arquitectura **Zero-Class-Rewrite** sobre `tkinter/ttk` utilizando el tema **Sun Valley (Fluent Design Windows 11)**:

* 🎨 **Tema Dinámico Claro/Oscuro:** Integración nativa con la barra de título de Windows 11 vía la API DWM (`DwmSetWindowAttribute`).
* 📊 **Tarjetas KPI en Tiempo Real:** Métricas en vivo de volumen escaneado, duplicados encontrados, espacio recuperable y tiempos de respuesta.
* 🔍 **Buscador y Filtro en Vivo:** Búsqueda instantánea de duplicados por nombre, extensión o ruta.
* 📈 **Series Temporales Integradas:** Gráfica interactiva de espacio recuperado con `matplotlib` (TkAgg).
* 🛡️ **Modal de Gestión de Cuarentena:** Inspecciona, restaura a sus rutas originales o purga sesiones de cuarentena con un clic.

### Atajos de Teclado Globales

| Atajo | Acción |
| :--- | :--- |
| <kbd>Ctrl</kbd> + <kbd>O</kbd> | Abrir selector de carpetas y escanear |
| <kbd>F5</kbd> | Re-escanear directorio actual |
| <kbd>Ctrl</kbd> + <kbd>F</kbd> | Enfocar barra de búsqueda de duplicados |
| <kbd>Ctrl</kbd> + <kbd>T</kbd> | Alternar tema visual (Modo Oscuro / Claro) |
| <kbd>Ctrl</kbd> + <kbd>Q</kbd> | Abrir panel de gestión de cuarentenas |
| <kbd>Ctrl</kbd> + <kbd>E</kbd> | Exportar reporte de auditoría a JSON |

---

## 💻 Modo Línea de Comandos (CLI)

El punto de entrada unificado `main.py` ofrece comandos completos con tablas formateadas mediante `rich`:

```bash
# 1. Auditar un directorio en modo seguro (Dry-Run / Simulación)
python main.py scan "C:\MisProyectos"

# 2. Trasladar duplicados a cuarentena reversible
python main.py quarantine "C:\MisProyectos"

# 3. Restaurar archivos desde un manifiesto de cuarentena
python main.py restore "C:\MisProyectos\_quarantine_20261109_001200\manifest.json"

# 4. Purgar definitivamente sesiones de cuarentena
python main.py purge "C:\MisProyectos"

# 5. Ver todas las opciones y banderas avanzadas
python main.py --help
```

---

## 🛡️ Los 4 Modos de Mitigación

| Modo | Mecanismo | Recuperabilidad | Impacto en Rutas | Caso de Uso Ideal |
| :--- | :--- | :---: | :---: | :--- |
| **📦 Cuarentena Soft-Delete** | Traslada los archivos redundantes a `_quarantine_<timestamp>/` con un `manifest.json` y firma `.sig`. | **$100\%$ Reversible** | Temporalmente rotas hasta restaurar | **Predeterminado recomendado:** Máxima seguridad y trazabilidad. |
| **🔗 Hardlinks (`os.link`)** | Reemplaza los duplicados por punteros físicos al mismo clúster de disco NTFS/ext4. | **Transparente** | **Intactas** (Cero rotura) | Proyectos de código, carpetas `node_modules`, bibliotecas y assets. |
| **🗑️ Papelera de Windows** | Envía los duplicados a la Papelera de reciclaje mediante la API nativa de `Send2Trash`. | **Manual** (Vía SO) | Vaciadas a la papelera | Limpiezas generales del usuario final. |
| **⚠️ Eliminación Permanente** | Desvincula atómicamente el inodo con verificación previa de descriptor en Kernel. | **Irreversible** | Eliminadas del disco | Servidores, backups o falta crítica de espacio. |

---

## 🧠 Reglas Inteligentes de Conservación

DataCleaner analiza heurísticamente los archivos en colisión para decidir cuál conservar de forma óptima:

1. **`deepest_then_newest` (Predeterminado):** Prefiere la ruta más anidada y limpia de nombres conflictivos (sin sufijos como `_copia`, `(1)`, `backup`), desempatando por la fecha más reciente.
2. **`deepest_then_oldest`:** Conserva la ruta más profunda priorizando la fecha de creación original.
3. **`shallowest_then_newest`:** Conserva el archivo más cercano a la raíz del escaneo.
4. **`newest_only`:** Conserva estrictamente el archivo con la fecha de modificación más reciente.
5. **`oldest_only`:** Conserva el archivo más antiguo.

---

## 🔒 Seguridad y Análisis Forense

DataCleaner fue diseñado siguiendo las especificaciones **NIST SSDF (SP 800-218)** y **EO 14028**:

* **Blindaje Anti-TOCTOU a Nivel de Kernel:** Antes de mover o eliminar un archivo, se abre su descriptor de sistema operativo (`os.open` con `O_NOFOLLOW`), se adquiere bloqueo exclusivo (`msvcrt.locking` en Windows / `fcntl.flock` en POSIX) y se validan atómicamente su tamaño y fecha mediante `os.fstat(fd)`. Si el archivo mutó tras el escaneo, la acción se cancela inmediatamente para prevenir pérdida de datos.
* **Firmas de Integridad HMAC-SHA256 (NIST SSDF PO.4):** Cada sesión de cuarentena genera un archivo `manifest.json.sig`. La clave criptográfica de 256 bits se almacena de forma persistente y protegida por listas de control de acceso de Windows (DACL `icacls`) en `%LOCALAPPDATA%\DataCleaner\.audit_key`, con fallback aleatorio en memoria RAM. Cualquier intento de adulterar el JSON invalida la restauración.
* **Inspección de Firmas Binarias (Magic Numbers / CWE-434):** Identifica el tipo MIME real mediante cabeceras binarias (PDF, PNG, JPG, ZIP, ejecutables PE/MZ, scripts Bash y Batch). Detecta amenazas comunes como:
  * Extensiones falseadas (ej. `factura.pdf` que en realidad es un ejecutable `MZ`).
  * Ataques de inversión de nombres con caracteres Unicode invisibles o RTLO (`\u202E`).
* **Protección de Rutas del Sistema:** Bloquea de forma estricta cualquier intento de escanear o manipular particiones raíz o directorios críticos como `Windows`, `Program Files`, `System32` o `AppData`.
* **Protección de Inodos en Sistemas Virtuales:** Exige `st_nlink > 1` antes de omitir hardlinks, garantizando que drivers virtuales (como Dokan/WinFsp o recursos SMB) no omitan archivos por colisión de inodos sintéticos.

---

## 📦 Compilación Nativa AOT con Nuitka

DataCleaner incluye un pipeline de compilación directa a lenguaje C generando un ejecutable nativo `.exe` de un solo archivo, libre de dependencias de Python:

```bash
# Compilar ejecutable nativo optimizado con SBOM y limpieza automática
python build_executable.py

# O ejecutar limpieza preventiva del espacio de trabajo
python build_executable.py --clean
```

El script de compilación ejecuta de forma automatizada:
1. **Limpieza profunda de artefactos:** Elimina `__pycache__`, archivos `.pyc` y bases SQLite temporales.
2. **Generación de SBOM (NIST SSDF PS.3.2):** Crea un inventario de software en formato CycloneDX (`cyclonedx-bom`).
3. **Detección y empaquetado de librerías Tcl/Tk:** Extrae automáticamente las dependencias gráficas incluso en entornos virtualizados `zipfs` (Python 3.15 / Tcl 9).
4. **Firma digital Authenticode (NIST SSDF PS.1.1):** Si la variable `CODESIGN_THUMBPRINT` está configurada, firma el binario con `signtool.exe`.

---

## 🗂️ Estructura del Código

```text
project-pc/
├── datacleaner/                # Paquete principal del motor
│   ├── scanner.py              # Pipeline Multi-Stage (Fase 1, 2 y 3) y recorrido asíncrono
│   ├── hasher.py               # Hashing C-level streaming (XXH3 / BLAKE / SHA-256)
│   ├── bloom.py                # Filtro de Bloom probabilístico en RAM (Kirsch-Mitzenmacher)
│   ├── security.py             # Motor de listas negras, claves HMAC y políticas de seguridad
│   ├── quarantine.py           # Cuarentena reversible, hardlinks y blindaje anti-TOCTOU
│   ├── magic.py                # Análisis forense e inspección de cabeceras binarias
│   ├── rules.py                # Heurística y scoring para decisión de archivos conservados
│   ├── reporter.py             # Generación de planes de auditoría y exportación JSON
│   ├── history.py              # Persistencia SQLite, Stateful Cache y series temporales
│   ├── scheduler.py            # Integración con el Programador de Tareas de Windows (schtasks)
│   ├── gui.py                  # Interfaz gráfica moderna Fluent Design Windows 11
│   └── cli.py                  # Interfaz de línea de comandos con tablas interactivas
├── tests/                      # Suite completa de pruebas unitarias y de estrés
│   ├── test_audit_fixes.py     # Pruebas de regresión y hardening de seguridad
│   ├── test_fallas_1_6.py      # Validación de fallas críticas corregidas
│   ├── test_fuzzing_resilience.py # Fuzzing de rutas, nombres Unicode y TOCTOU
│   ├── test_hardening.py       # Pruebas de concurrencia y límites del sistema operativo
│   ├── test_hasher.py          # Pruebas bit a bit de algoritmos de dispersión
│   ├── test_quarantine_restore.py # Pruebas de cuarentena, restauración y hardlinks
│   ├── test_rules.py           # Pruebas de heurística de selección de archivos
│   ├── test_scanner.py         # Pruebas del orquestador del escáner
│   └── test_security.py        # Pruebas de lista negra de rutas críticas
├── build_executable.py         # Compilador AOT Nuitka con CycloneDX SBOM
├── iniciar.bat                 # Lanzador rápido de un clic para Windows
├── main.py                     # Punto de entrada unificado (GUI y CLI)
├── pyproject.toml              # Metadatos del proyecto y configuración de herramientas
├── requirements.txt            # Dependencias del proyecto
└── SECURITY.md                 # Política de seguridad y divulgación coordinada (CVD)
```

---

## 🧪 Pruebas Unitarias y Calidad

El proyecto cuenta con una cobertura de pruebas exhaustiva, verificando robustez ante condiciones de carrera, ataques forenses y cargas masivas:

```bash
# Ejecutar la suite completa de pruebas unitarias
pytest tests/ -v
```

```text
============================= 83 passed in ~12.5s =============================
```

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.
