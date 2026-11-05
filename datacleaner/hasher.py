"""
Módulo de Hashing Criptográfico y Dispersión Escalonada (Multi-Stage Hashing)
DataCleaner CLI/GUI

Implementa el pipeline de evaluación en tres fases (O(1) -> O(k) -> O(n)):
- Fase 1 (O(1)): Colisión de st_size (manejada en scanner.py).
- Fase 2 (O(k)): Fast Hash / Hash Parcial sobre el primer y último fragmento (chunk) de 64 KB.
- Fase 3 (O(n)): SHA-256 criptográfico completo por bloques de 64 KB (solo si la Fase 2 colisiona).

Protección contra saturación de descriptores de archivos del sistema operativo (Too many open files),
control riguroso de concurrencia y manejo seguro de excepciones por archivos bloqueados.
"""

import hashlib
import os
from pathlib import Path
from typing import Callable

try:
    import xxhash
    HAS_XXHASH = True
except ImportError:
    HAS_XXHASH = False

DEFAULT_CHUNK_SIZE = 65536  # 64 KB por bloque según especificación RF-03 y Fase 2 Multi-Stage
MIN_WORKERS = 1
MAX_SAFE_WORKERS = 8  # Límite superior seguro para evitar agotamiento de descriptores de archivo


def get_safe_worker_count(requested_workers: int | None = None) -> int:
    """
    Calcula un número seguro de trabajadores para ThreadPoolExecutor.
    Previene el agotamiento de descriptores de archivo del sistema operativo
    (Too many open files) regulando entre 2 y 4 para HDD o hasta 8 para SSD multinúcleo.
    """
    if requested_workers is None:
        cpu = os.cpu_count() or 4
        return min(max(cpu, 2), MAX_SAFE_WORKERS)
    if requested_workers <= 0:
        return MIN_WORKERS
    return max(MIN_WORKERS, min(requested_workers, 16))


def _new_fast_hasher():
    """
    Retorna un motor de hash ultrarrápido no criptográfico (xxHash64 si está instalado)
    o BLAKE2b de 128 bits (implementado en C nativo en la librería estándar de Python,
    significativamente más veloz que SHA-256 para descarte de bordes O(k)).
    """
    if HAS_XXHASH:
        return xxhash.xxh64()
    return hashlib.blake2b(digest_size=16)


def compute_partial_hash(
    file_path: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    on_error: Callable[[str], None] | None = None
) -> str | None:
    """Calcula un hash preliminar rápido leyendo solo los extremos del archivo."""
    fast_hash = hashlib.md5()  # MD5 es más veloz y suficiente para descarte preliminar
    try:
        file_size = file_path.stat().st_size
        with open(file_path, "rb") as f:
            # 1. Leer cabecera (Magic Numbers y primeros metadatos)
            fast_hash.update(f.read(chunk_size))

            # 2. Leer cola (Firmas de cierre y EOF)
            if file_size > chunk_size * 2:
                f.seek(-chunk_size, os.SEEK_END)
                fast_hash.update(f.read(chunk_size))

        return fast_hash.hexdigest()
    except (PermissionError, OSError, FileNotFoundError, IOError) as exc:
        if on_error:
            on_error(f"Error en lectura parcial de '{file_path}': {exc}")
        return None


def compute_file_hash(
    file_path: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    on_error: Callable[[str], None] | None = None
) -> str | None:
    """
    Fase 3 (O(n)) del Algoritmo de Dispersión Escalonada:
    Calcula el hash criptográfico SHA-256 completo de un archivo leyendo por bloques fijos
    de 64 KB para optimizar memoria RAM. Se ejecuta únicamente cuando la Fase 2 (Fast Hash)
    confirmó colisión en los fragmentos inicial y final.

    Args:
        file_path: Ruta al archivo a procesar.
        chunk_size: Tamaño de bloque de lectura en bytes (por defecto 64 KB).
        on_error: Función de retorno opcional para registrar advertencias de lectura sin detener el hilo.

    Returns:
        Hexdigest SHA-256 en minúsculas, o None si el archivo no puede ser leído
        debido a permisos, archivo en uso o bloqueos del sistema operativo.
    """
    sha256_hash = hashlib.sha256()
    try:
        # El bloque 'with' asegura el cierre determinista del descriptor de archivo (fd)
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(chunk_size), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, OSError, FileNotFoundError, IOError) as exc:
        # Manejo no destructivo: registra la advertencia y continúa con el siguiente archivo
        if on_error:
            on_error(f"No se pudo leer '{file_path}': {exc}")
        return None
