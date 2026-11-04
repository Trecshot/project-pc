"""
Motor de Escaneo y Detección de Duplicados (Core Engine)
DataCleaner CLI/GUI

Escaneo concurrente de directorios mediante ThreadPoolExecutor,
pre-filtrado por tamaño para reducir E/S innecesaria y cálculo de SHA-256
por bloques. Cumple con RF-03, RF-04, RNF-01 y RNF-02.
"""

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Generator
import os

from datacleaner.hasher import compute_file_hash, DEFAULT_CHUNK_SIZE

@dataclass
class ScanSummary:
    """Metadatos globales del proceso de auditoría."""
    base_dir: Path
    total_files_scanned: int = 0
    total_bytes_scanned: int = 0
    duplicate_groups_count: int = 0
    total_duplicate_files: int = 0
    recoverable_bytes: int = 0
    unreadable_files_count: int = 0

def iter_directory_files(base_dir: Path) -> Generator[Path, None, None]:
    """
    Generador perezoso que itera sobre los archivos del directorio base recursivamente,
    ignorando subdirectorios de cuarentena para evitar bucles o falsos positivos.
    """
    try:
        for entry in base_dir.rglob("*"):
            # Omitir carpetas de cuarentena previas
            if any(part.startswith("_quarantine_") for part in entry.parts):
                continue
            try:
                if entry.is_file() and not entry.is_symlink():
                    yield entry
            except (PermissionError, OSError):
                continue
    except (PermissionError, OSError):
        return

def scan_directory_for_duplicates(
    base_dir: Path,
    max_workers: int = 4,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Callable[[int, int, str], None] | None = None
) -> tuple[dict[str, list[Path]], ScanSummary]:
    """
    Escanea recursivamente un directorio seguro y agrupa archivos por su hash SHA-256.

    Estrategia de rendimiento (Zero RAM Bottleneck):
    1. Agrupación preliminar por tamaño de archivo (st_size) en O(1) de metadatos.
       Los archivos de tamaño único se descartan de inmediato sin leer su contenido del disco.
    2. Hashing SHA-256 concurrente por bloques (chunked) exclusivamente sobre candidatos que
       comparten el mismo tamaño en bytes.
    3. Indexación de colisiones reales bit a bit en memoria (dict[hash, list[Path]]).

    Args:
        base_dir: Directorio validado a auditar.
        max_workers: Número de hilos en el ThreadPoolExecutor para operaciones de I/O.
        chunk_size: Tamaño de bloque de lectura binaria (bytes).
        progress_callback: Función opcional callback(procesados, total, archivo_actual).

    Returns:
        Tupla con:
        - Diccionario de hashes duplicados: {sha256: [ruta1, ruta2, ...]} (len(paths) > 1)
        - Resumen estadístico ScanSummary
    """
    summary = ScanSummary(base_dir=base_dir)

    # Paso 1: Mapeo preliminar por tamaño de archivo usando generador perezoso
    size_map: dict[int, list[Path]] = {}
    for file_path in iter_directory_files(base_dir):
        summary.total_files_scanned += 1
        try:
            stat = file_path.stat()
            file_size = stat.st_size
            summary.total_bytes_scanned += file_size

            # Ignorar archivos vacíos de 0 bytes o tratarlos opcionalmente
            # (los agrupamos para auditar colisiones)
            if file_size not in size_map:
                size_map[file_size] = []
            size_map[file_size].append(file_path)
        except (PermissionError, OSError):
            summary.unreadable_files_count += 1
            continue

    # Filtrar solo aquellos archivos cuyos tamaños colisionan con al menos otro archivo
    candidate_files: list[Path] = []
    for f_size, paths in size_map.items():
        if len(paths) > 1:
            candidate_files.extend(paths)

    total_candidates = len(candidate_files)
    if total_candidates == 0:
        return {}, summary

    # Paso 2: Cálculo concurrente de SHA-256 mediante ThreadPoolExecutor
    hash_map: dict[str, list[Path]] = {}

    def _process_candidate(fp: Path) -> tuple[str | None, Path]:
        return compute_file_hash(fp, chunk_size=chunk_size), fp

    processed_count = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_process_candidate, fp): fp for fp in candidate_files}

        for future in as_completed(futures):
            processed_count += 1
            res_hash, f_path = future.result()

            if progress_callback:
                progress_callback(processed_count, total_candidates, str(f_path.name))

            if res_hash:
                if res_hash not in hash_map:
                    hash_map[res_hash] = []
                hash_map[res_hash].append(f_path)
            else:
                summary.unreadable_files_count += 1

    # Paso 3: Filtrar para conservar únicamente hashes con más de 1 archivo (duplicados reales)
    duplicates: dict[str, list[Path]] = {}
    recoverable_bytes = 0
    total_dup_files = 0

    for h, paths in hash_map.items():
        if len(paths) > 1:
            duplicates[h] = paths
            try:
                single_file_size = paths[0].stat().st_size
            except (OSError, IndexError):
                single_file_size = 0
            
            # Espacio recuperable = tamaño de cada copia redundante (excluyendo 1 que se conserva)
            redundant_count = len(paths) - 1
            recoverable_bytes += (single_file_size * redundant_count)
            total_dup_files += len(paths)

    summary.duplicate_groups_count = len(duplicates)
    summary.total_duplicate_files = total_dup_files
    summary.recoverable_bytes = recoverable_bytes

    return duplicates, summary
