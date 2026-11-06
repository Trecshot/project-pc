# 🛡️ DataCleaner

**Auditoría Inteligente, Forense Binaria y Deduplicación de Archivos bajo Política de Cero Pérdida de Datos**

DataCleaner es una herramienta de escritorio (interfaz gráfica moderna Fluent Design) y de línea de comandos (CLI) diseñada para auditar, organizar y deduplicar archivos bit a bit de forma segura, garantizando la integridad de tus datos y del sistema operativo.

---

## 🎯 ¿Qué hace DataCleaner?

1. **Detección Escalonada de Duplicados (Multi-Stage Hashing)**:
   - **Fase 1 (Filtro de Bloom en RAM)**: Agrupa instantáneamente por tamaño de archivo con `BloomFilter` descartando elementos únicos en memoria RAM (< 15 MB para más de 500k archivos) sin realizar lecturas previas en disco.
   - **Fase 2 (Fast-Hash 128 KB)**: Lee únicamente los primeros y últimos 64 KB de los archivos candidatos mediante streaming ultra-rápido en RAM (XXH3 / BLAKE / SHA-256 + seek) para descartar falsas colisiones (NIST SP 800-131A / FIPS 140-3).
   - **Fase 3 (SHA-256 Completo)**: Calcula el hash criptográfico bit a bit solo cuando los extremos colisionan, garantizando coincidencia exacta al 100%.

2. **Seguridad y Cero Pérdida de Datos**:
   - **Blindaje Anti-TOCTOU**: Verifica atómicamente el tamaño y la fecha de modificación antes de cualquier acción. Si un archivo mutó tras el escaneo, la operación se cancela automáticamente para proteger datos nuevos.
   - **Protección de Rutas Críticas**: Bloquea de forma estricta cualquier escaneo o modificación en directorios esenciales del sistema (`Windows`, `Program Files`, `System32`, `AppData`, y particiones raíz).
   - **Análisis Forense (Magic Numbers)**: Inspecciona las cabeceras binarias reales (`PDF`, `PNG`, `JPG`, `ZIP`, ejecutables `MZ`/`ELF`) para alertar sobre extensiones falsas o ejecutables camuflados.

3. **4 Modos de Limpieza y Mitigación**:
   - **Cuarentena Reversible (Soft-Delete)**: Traslada los duplicados a una carpeta de aislamiento con un archivo `manifest.json`, permitiendo restaurarlos a su ubicación original en un clic.
   - **Hardlinks a Nivel de SO (`os.link`)**: Libera el 100% del espacio redundante haciendo que los archivos duplicados apunten al mismo sector físico en disco sin moverlos ni romper rutas de tus proyectos.
   - **Papelera de Reciclaje**: Envía los duplicados a la Papelera de Windows para un borrado recuperable.
   - **Eliminación Permanente**: Borrado definitivo del disco previa confirmación explícita.

4. **Caché Inteligente y Rendimiento**:
   - Reutiliza hashes calculados previamente mediante una base de datos local SQLite (`.datacleaner.sqlite`), acelerando re-escaneos en $O(1)$ sin volver a leer el disco.
   - Motor multihilo nativo que satura el bus de lectura de unidades SSD/NVMe liberando el GIL en C.

---

## 🗂️ Estructura del Proyecto

```text
datacleaner/
├── scanner.py      # Pipeline de detección en 3 fases y orquestación del escaneo.
├── hasher.py       # Algoritmos de lectura parcial ultra-rápida (XXH3/BLAKE) y SHA-256 criptográfico en C.
├── bloom.py        # Filtro de Bloom probabilístico en RAM para contención de memoria en Fase 1.
├── security.py     # Lista negra del sistema operativo y validación estricta de rutas.
├── quarantine.py   # Manejo de cuarentena reversible, hardlinks, papelera y validación anti-TOCTOU.
├── reporter.py     # Construcción del plan de auditoría, snapshots de metadatos y reportes.
├── rules.py        # Reglas inteligentes para decidir qué archivo conservar (rutas limpias, fechas, etc.).
├── history.py      # Persistencia transaccional SQLite, Stateful Cache y series temporales.
├── magic.py        # Auditoría forense e inspección de firmas binarias reales (Magic Numbers).
├── scheduler.py    # Integración con el Programador de Tareas de Windows (schtasks.exe).
├── gui.py          # Interfaz gráfica moderna con Fluent Design Windows 11 y tema claro/oscuro.
└── cli.py          # Interfaz de consola con reportes y tablas interactivas.

main.py             # Punto de entrada unificado para iniciar la aplicación (GUI o CLI).
iniciar.bat         # Lanzador rápido de un clic para Windows.
```
