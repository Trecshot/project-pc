# DataCleaner (CLI & GUI)
**Gestor Local de Organización y Auditoría de Archivos por Hash SHA-256**

DataCleaner es una utilidad de software orientada a la auditoría, análisis de redundancias y estructuración de directorios en almacenamiento secundario local. Resuelve el problema del almacenamiento caótico identificando con precisión duplicados binarios idénticos bit a bit (independientemente del nombre del archivo) bajo una estricta política de **Cero Pérdida de Datos**.

---

## 1. Principios Rectores (Cero Pérdida de Datos)

1. **Simulación Obligatoria (Dry-Run):** Ninguna operación modificatoria o de traslado se ejecuta sobre el disco sin una previsualización previa y aprobación explícita del usuario.
2. **Aislamiento de Rutas Críticas (Blacklist):** Mecanismo estricto a nivel de código que intercepta y bloquea cualquier intento de auditar directorios del sistema operativo (`C:\Windows`, `Program Files`, `/etc`, etc.) o particiones raíz completas (`C:\`, `/`).
3. **Cuarentena No Destructiva (Soft-Delete):** Los archivos redundantes no se eliminan permanentemente con `os.remove`. Se trasladan a una carpeta dedicada `./_quarantine_timestamp/` replicando su árbol relativo de directorios y generando un `manifest.json` que permite su **restauración inmediata reversible**.

---

## 2. Arquitectura del Sistema

El software sigue un patrón modular desacoplado en capas:

```
┌────────────────────────────────────────────────────────┐
│               Capa de Interfaz de Usuario              │
│            (CLI con Rich / GUI CustomTkinter)          │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│             Capa de Seguridad y Validación             │
│        (Filtros de Blacklist & Control de Rutas)       │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│                Motor de Escaneo y Hash                 │
│    (Filtrado por Tamaño & Hashing SHA-256 por Chunks)  │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│          Subsistema de Cuarentena y Reportes           │
│    (Soft-Delete, JSON State, Restore & Bitácora)       │
└────────────────────────────────────────────────────────┘
```

### Estructura del Proyecto

```
project-pc/
├── datacleaner/
│   ├── __init__.py         # Exportaciones principales del paquete
│   ├── security.py         # Motor de seguridad, Blacklist y control de particiones raíz (RF-01, RF-02)
│   ├── hasher.py           # Cálculo de huella SHA-256 por bloques de 64 KB (RF-03, RNF-01)
│   ├── scanner.py          # Recorrido recursivo concurrente con ThreadPoolExecutor (RF-04, RNF-02)
│   ├── rules.py            # Criterios de permanencia (Keep Rules: profundidad, limpieza, mtime)
│   ├── quarantine.py       # Aislamiento no destructivo y motor reversible de restauración (RF-06)
│   ├── reporter.py         # Generación de reportes Dry-Run con Rich y exportación JSON (RF-05)
│   ├── cli.py              # Interfaz de Línea de Comandos con Rich
│   └── gui.py              # Interfaz Gráfica de Escritorio (Desktop GUI con Tkinter)
├── tests/
│   ├── test_security.py    # Pruebas de validación de rutas y lista negra
│   ├── test_hasher.py      # Pruebas de hashing por bloques y archivos grandes
│   ├── test_scanner.py     # Pruebas de escaneo concurrente y colisiones
│   ├── test_rules.py       # Pruebas de criterios de selección
│   └── test_quarantine_restore.py # Pruebas del ciclo completo de cuarentena y reversión
├── main.py                 # Punto de entrada universal
├── pyproject.toml          # Metadatos del paquete instalable
├── requirements.txt        # Dependencias externas (rich)
└── README.md               # Documentación técnica y guía de uso
```

---

## 3. Requerimientos Técnicos Cumplidos

| Requerimiento | Descripción | Implementación |
| :--- | :--- | :--- |
| **RF-01** | Selección explícita de directorio | Requiere path explícito; bloquea unidades de disco raíz (`C:\`, `/`). |
| **RF-02** | Validación contra lista negra | `SYSTEM_BLACKLIST` previene inspección de carpetas de Windows, Linux y macOS. |
| **RF-03** | Chunked Hashing (64 KB) | `compute_file_hash` procesa en bloques de 65,536 bytes; no satura la RAM. |
| **RF-04** | Detección de colisiones exactas | Agrupación en `dict[hash, list[Path]]` tras pre-filtrado por tamaño en bytes. |
| **RF-05** | Reporte previo (Dry-Run) | Muestra tablas Rich formateadas y permite exportar auditoría en JSON estructurado. |
| **RF-06** | Cuarentena controlada (Soft-Delete) | Mueve archivos a `_quarantine_timestamp/`, replica estructura relativa y crea `manifest.json`. |
| **RNF-01** | Límite estricto de RAM (<150 MB) | Generadores perezosos (`iter_directory_files`) y lectura por bloques sin cargar archivos a memoria. |
| **RNF-02** | Concurrencia de E/S | `ThreadPoolExecutor` para hashing en paralelo de candidatos duplicados. |
| **RNF-03** | Portabilidad Multiplataforma | 100% `pathlib.Path`, compatible con Windows, Linux y macOS. |

---

## 4. Instalación

Requiere **Python 3.10 o superior**.

```bash
# Clonar o ubicarse en el directorio del proyecto
cd project-pc

# Instalar dependencias
pip install -r requirements.txt

# (Opcional) Instalar en modo editable para tener el comando global 'datacleaner'
pip install -e .
```

---

## 5. Guía de Uso

### 5.1 Modo Interfaz de Línea de Comandos (CLI)

#### 1. Auditoría de Simulación (Dry-Run por defecto)
Escanea el directorio objetivo, identifica duplicados y presenta el reporte sin modificar ningún archivo:
```bash
datacleaner scan "C:\MisDocumentos"
```

Opciones disponibles para `scan`:
- `--keep-rule`: Criterio para decidir qué archivo conservar (`deepest_then_newest`, `deepest_then_oldest`, `shallowest_then_newest`, `newest`, `oldest`).
- `--workers <N>`: Número de hilos paralelos para hashing de E/S (por defecto: 4).
- `--json-out <archivo.json>`: Exporta el reporte completo en formato JSON.
- `-i, --interactive`: Tras mostrar el reporte, pregunta si se desea ejecutar la cuarentena de inmediato.

Ejemplo:
```bash
datacleaner scan "C:\Proyectos" --workers 8 --keep-rule deepest_then_newest --json-out reporte_auditoria.json
```

#### 2. Ejecución Controlada de Cuarentena (Soft-Delete)
Traslada las copias redundantes a una carpeta dedicada `./_quarantine_YYYYMMDD_HHMMSS/`:
```bash
datacleaner quarantine "C:\MisDocumentos"
```
*Por defecto solicita confirmación interactiva `[s/N]`. Para scripts automatizados se puede agregar la bandera `-y` o `--yes`.*

#### 3. Restauración Automatizada Reversible (Restore)
Devuelve de manera segura e idéntica los archivos de la cuarentena a sus rutas originales:
```bash
datacleaner restore "C:\MisDocumentos\_quarantine_20261104_154641\manifest.json"
```

---

### 5.2 Modo Interfaz Gráfica (Desktop GUI con Sun Valley TTK - Fluent Design)

Para iniciar la interfaz gráfica de usuario con diseño Fluent Design Windows 11:
```bash
datacleaner gui
# o alternativamente:
python main.py --gui
```

**Ventajas Arquitecturales y Mejoras de Accesibilidad (A11y / WCAG):**
- **Arquitectura Zero-Class-Rewrite:** Utiliza las clases estándar de `tkinter.ttk` inyectando el tema moderno Sun Valley vía `sv-ttk`, asegurando compatibilidad nativa sin necesidad de reescribir la lógica de la vista ni romper dependencias.
- **Fluent Design Windows 11:** Bordes redondeados sutiles, microinteracciones (hover/active) y botones de acción destacados con `Accent.TButton`.
- **Gestión Centralizada de Tema:** Botón superior para alternar instantáneamente entre **Modo Oscuro** (`sun-valley-dark`) y **Modo Claro** (`sun-valley-light`).
- **Validación en Línea No Bloqueante:** Sustituye ventanas emergentes por mensajes visuales directos en la tarjeta de selección, activando el botón de escaneo solo cuando la ruta es segura y válida.
- **Aislamiento de Tecnicismos:** El conteo de hilos de trabajo se calibra automáticamente según el CPU (`os.cpu_count()`) y se ubica junto a las reglas de permanencia en el panel desplegable `⚙ Opciones avanzadas ▼`.
- **Lenguaje Instruccional Directo:** Guía clara paso a paso: *"1. Seleccione una carpeta. 2. Escanee en busca de duplicados. Ningún archivo será borrado sin su confirmación"*.
- **Dashboard de Alto Contraste:** Tarjetas estilo `Card.TFrame` con tipografía de alto peso visual (`font=("Segoe UI", 18, "bold")`) para cumplimiento de contraste WCAG.
- **Tabla Simplificada de Duplicados:** Hash SHA-256 ofuscado a 8 caracteres (`c2aeccb6…`) para priorizar Grupo, Estado/Acción (`KEEP` / `QUARANTINE`), Tamaño y Ruta del Archivo.

---

## 6. Criterios de Permanencia (Keep Rules)

Cuando se detecta un grupo de colisión SHA-256 (2 o más archivos idénticos), el sistema evalúa cuál sobrevive mediante los siguientes criterios configurables:

1. **Criterio de Limpieza y Profundidad de Ruta (`deepest_then_newest` - Por defecto):**
   - Se priorizan rutas estructuradas en subcarpetas de proyectos frente a carpetas genéricas o provisionales (`Downloads`, `Temp`, `Descargas`, `Cache`, `Copia`).
   - A igualdad de condiciones, se conserva el archivo con fecha de modificación más reciente.
2. **`deepest_then_oldest`:** Mayor profundidad y limpieza de ruta, conservando la copia más antigua.
3. **`shallowest_then_newest`:** Conserva el archivo más cercano a la raíz del directorio analizado.
4. **`newest`:** Conserva exclusivamente el archivo modificado más recientemente.
5. **`oldest`:** Conserva exclusivamente el archivo original más antiguo.

---

## 7. Ejecución de Pruebas Unitarias

El proyecto incluye 17 pruebas unitarias sin dependencias externas (usando `unittest` nativo):

```bash
python -m unittest discover tests -v
```

Cobertura de pruebas:
- `test_security.py`: Validación de rutas seguras, bloqueo de unidades raíz (`C:\`, `/`) y protección de `SYSTEM_BLACKLIST`.
- `test_hasher.py`: Exactitud de SHA-256, lectura por bloques de 64 KB y tolerancia a fallos.
- `test_rules.py`: Evaluación de profundidad, penalización de carpetas de descargas/temporales y fechas de modificación.
- `test_scanner.py`: Escaneo concurrente, discriminación de falsos positivos (mismo tamaño pero diferente contenido) e ignorado de carpetas de cuarentena previas.
- `test_quarantine_restore.py`: Verificación del ciclo completo de Soft-Delete, estructura relativa de directorios, generación de `manifest.json`, restauración exacta bit a bit, purgado de sesiones y eliminación directa/papelera.

---

## 8. Modos de Limpieza y Gestión de Duplicados

DataCleaner ofrece tres esquemas flexibles de mitigación de redundancias:

1. **Opción Recomendada: Aislamiento en Cuarentena y Purgado Diferido (Vaciar Cuarentena)**
   - **Fase 1 (Aislamiento):** Los archivos duplicados se trasladan de forma no destructiva a `./_quarantine_timestamp/`, manteniendo el árbol de directorios original y creando un `manifest.json`.
   - **Fase 2 (Restauración o Purgado):** Mediante el modal interactivo de la GUI o el botón *"Vaciar Cuarentena (Purgar)"*, el usuario puede restaurar los archivos a su origen o destruir definitivamente la carpeta de cuarentena una vez confirmado el buen funcionamiento del sistema (`purge_quarantine_session()`).
   - CLI: `datacleaner purge <directorio>`

2. **Opción Directa: Eliminación Permanente (Irreversible)**
   - Borrado inmediato de disco mediante `Path.unlink()` sobre los archivos redundantes sin generar carpetas de cuarentena.
   - Requiere confirmación explícita mediante diálogo crítico de advertencia en la GUI o la bandera `--permanent` en CLI.

3. **Papelera de Reciclaje de Windows (`send2trash`)**
   - Elimina el archivo de su directorio de origen liberando espacio de inmediato, pero enviándolo a la Papelera de Reciclaje nativa del sistema operativo.
   - Permite recuperar cualquier archivo directamente desde la papelera de Windows sin requerir restauraciones manuales.

