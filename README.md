# 🛡️ DataCleaner (CLI & GUI)
**Auditoría Inteligente, Forense Binaria y Deduplicación de Archivos bajo Política de Cero Pérdida de Datos**

DataCleaner es una herramienta de escritorio y consola (Windows 11 Fluent Design / CLI) para detectar y mitigar archivos duplicados exactos bit a bit sin comprometer la integridad del sistema ni de tus proyectos.

---

## ✨ Lo Destacado

- ⚡ **Multi-Stage Hashing (`O(1)` → `O(k)` → `O(n)`)**:
  1. **Fase 1 (`st_size` + Bloom Filter en RAM)**: Agrupación instantánea por tamaño y descarte probabilístico $O(1)$ con huella de RAM casi nula (< 50 KB para millones de archivos).
  2. **Fase 2 (`Fast-Hash 128 KB`)**: Lectura exclusiva del primer y último bloque de `64 KB` (`MD5` + `seek`) para descartar falsas colisiones en archivos masivos (ISOs, contenedores, bases de datos) sin leer el archivo completo.
  3. **Fase 3 (`SHA-256`)**: Verificación criptográfica completa solo cuando los extremos colisionan.
- 🚀 **Caché de Estado Hashed (Stateful Caching `O(1)`) & E/S Asíncrona**:
  - Re-escaneos instantáneos: si el archivo no ha mutado (`st_mtime` y tamaño), su hash se recupera desde SQLite en $O(1)$ sin tocar el disco.
  - Motor asíncrono con `asyncio` y `aiofiles` (`asyncio.Semaphore`) para exprimir el bus de lectura de discos SSD/NVMe sin contención del GIL.
- 🔬 **Auditoría Forense por Firmas Binarias (`Magic Numbers`)**: Inspecciona las cabeceras hexadecimales reales (`%PDF`, `PNG`, `JPEG`, `ZIP`, `SQLite3`, ejecutables `MZ`/`ELF`) para detectar extensiones manipuladas o ejecutables camuflados como documentos.
- 🔗 **4 Modos de Mitigación y Limpieza**:
  1. **Cuarentena Reversible (`Soft-Delete`)**: Aísla duplicados en `_quarantine_*/` con `manifest.json` para restaurar en un clic o vaciar/purgar sesiones cuando estés seguro.
  2. **Deduplicación Transparente con Hardlinks (`os.link`)**: Libera el 100% del espacio redundante apuntando las copias al mismo clúster físico en disco **sin mover ni borrar ninguna ruta** (ideal para repositorios y dependencias).
  3. **Papelera de Reciclaje Nativa (`send2trash`)**: Libera espacio enviando duplicados a la Papelera de Windows.
  4. **Eliminación Permanente (`unlink`)**: Borrado definitivo previa confirmación explícita.
- 🏆 **Historial Transaccional SQLite y Conversión Dinámica (`MB ↔ GB ↔ TB`)**:
  - Motor relacional local en SQLite (`.datacleaner.sqlite`) con consultas agregadas (`SUM`, `COUNT`) en C nativo.
  - Escalado inteligente de unidades (`B → KB → MB → GB → TB`) y equivalencias simultáneas (`MB ↔ GB`).
- 🎨 **Interfaz Moderna y Accesible (WCAG AA)**:
  - Tema **Fluent Design Windows 11** (`sv-ttk`) con barra de título nativa en Modo Oscuro / Claro, accesos rápidos a carpetas de usuario, filtrado en vivo y atajos de teclado (`F5`, `Ctrl+O`, `Ctrl+G`, `Ctrl+F`).

---

## 🚀 Instalación y Arranque Rápido

Requiere **Python 3.10+**.

```bash
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Iniciar la Interfaz Gráfica (Modo por defecto)
python main.py
```

### Comandos Rápidos por Consola (CLI)

```bash
# Simulación segura (Dry-Run)
python main.py scan "C:\MisDocumentos"

# Aislar duplicados en cuarentena
python main.py quarantine "C:\MisDocumentos"

# Restaurar una sesión de cuarentena
python main.py restore "C:\MisDocumentos\_quarantine_YYYYMMDD_HHMMSS\manifest.json"

# Vaciar/purgar sesiones de cuarentena
python main.py purge "C:\MisDocumentos"
```

---

## 🗂️ Estructura Principal

```text
datacleaner/
├── gui.py          # Interfaz Fluent Design Windows 11, Gráfica Analítica y Tareas Programadas
├── scanner.py      # Pipeline Multi-Stage Asíncrono (Bloom Filter -> Fast-Hash -> SHA-256)
├── hasher.py       # Hashing parcial (MD5 seek) y SHA-256 síncrono/asíncrono (aiofiles)
├── bloom.py        # Filtro de Bloom probabilístico optimizado en bytearray (RAM O(1))
├── magic.py        # Validación forense de cabeceras binarias (Magic Numbers / MIME)
├── quarantine.py   # Soft-Delete, Restauración, Purgado, Hardlinks OS-Level y Papelera
├── history.py      # Persistencia SQLite (.datacleaner.sqlite), Stateful Cache y serie temporal
├── rules.py        # Reglas de conservación (profundidad, limpieza de ruta y fecha)
└── security.py     # Protección estricta contra rutas críticas del sistema (Blacklist)
```

---

## 🧪 Pruebas Automatizadas

Cuenta con **38 pruebas unitarias** que validan seguridad, pipeline Multi-Stage, firmas Magic Numbers, hardlinks, ciclo de cuarentena/restauración, Stateful Cache, Bloom Filters y E/S asíncrona:

```bash
python -m pytest -v
```
