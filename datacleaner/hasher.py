"""
Módulo de Hashing Criptográfico por Bloques
DataCleaner CLI/GUI

Implementa el cálculo de huellas digitales SHA-256 mediante lectura por chunks (64 KB)
para minimizar el consumo de memoria RAM (<150 MB) y garantizar tolerancia a fallos de permisos.
Cumple con RF-03 y RNF-01.
"""

import hashlib
from pathlib import Path

DEFAULT_CHUNK_SIZE = 65536  # 64 KB por bloque según especificación RF-03

def compute_file_hash(file_path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str | None:
    """
    Calcula el hash SHA-256 de un archivo leyendo por bloques fijos para optimizar memoria RAM.

    Args:
        file_path: Ruta al archivo a procesar.
        chunk_size: Tamaño de bloque de lectura en bytes (por defecto 64 KB).

    Returns:
        Hexdigest SHA-256 en minúsculas, o None si el archivo no puede ser leído
        debido a permisos o bloqueos del sistema operativo.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(chunk_size), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, OSError, FileNotFoundError):
        # Manejo no destructivo: ignora archivos bloqueados o sin permisos de lectura
        return None
