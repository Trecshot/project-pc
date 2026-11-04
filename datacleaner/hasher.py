"""
Módulo de Hashing Criptográfico por Bloques (Hardened)
DataCleaner CLI/GUI

Implementa el cálculo de huellas digitales SHA-256 mediante lectura por chunks (64 KB).
Protección contra saturación de descriptores de archivos del sistema operativo (Too many open files),
control riguroso de concurrencia y manejo seguro de excepciones por archivos bloqueados.
Cumple con RF-03, RNF-01 y las directrices de hardening de E/S.
"""

import hashlib
import os
from pathlib import Path
from typing import Callable

DEFAULT_CHUNK_SIZE = 65536  # 64 KB por bloque según especificación RF-03
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

def compute_file_hash(
    file_path: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    on_error: Callable[[str], None] | None = None
) -> str | None:
    """
    Calcula el hash SHA-256 de un archivo leyendo por bloques fijos para optimizar memoria RAM.
    Garantiza el cierre inmediato del descriptor de archivo mediante bloque contextual 'with open'.

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
