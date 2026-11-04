"""
Motor de Escaneo y Detección de Duplicados (Hardened Core Engine)
DataCleaner CLI/GUI

Escaneo concurrente de directorios mediante ThreadPoolExecutor.
Protección estricta contra bucles infinitos por enlaces simbólicos (symlinks) y uniones (junctions en Windows).
Manejo no destructivo de archivos bloqueados por el sistema operativo mediante registro de advertencias.
Cumple con RF-03, RF-04, RNF-01, RNF-02 y las directrices de hardening.
"""

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Generator
import os

from datacleaner.hasher import compute_file_hash, get_safe_worker_count, DEFAULT_CHUNK_SIZE

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
    warnings: list[str] = field(default_factory=list)

def is_symlink_or_junction(path: Path) -> bool:
    """
    Detecta si una ruta es un enlace simbólico o una unión de directorios (Junction en NTFS/Windows).
    Previene recursión infinita y conteos duplicados.
    """
    try:
        # 1. Comprobación de enlace simbólico estándar
        if path.is_symlink() or os.path.islink(path):
            return True

        # 2. Comprobación de junction en Windows (Python 3.12+)
        if hasattr(path, "is_junction") and path.is_junction():
            return True

        # 3. Verificación de atributos reparse point en Windows
        stat_result = path.stat(follow_symlinks=False)
        if hasattr(stat_result, "st_file_attributes"):
            FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
            if stat_result.st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                return True

        return False
    except (PermissionError, OSError):
        # En caso de error de acceso en el enlace, tratarlo como protegido/enlace para omitirlo
        return True

def iter_directory_files(base_dir: Path, on_warning: Callable[[str], None] | None = None) -> Generator[Path, None, None]:
    """
    Generador perezoso que recorre el directorio base sin seguir enlaces simbólicos ni uniones.
    Usa os.walk con followlinks=False para máxima seguridad y rendimiento de memoria.
    """
    try:
        for root, dirs, files in os.walk(base_dir, followlinks=False):
            root_path = Path(root)

            # Modificar 'dirs' in-place para podar carpetas que no deben explorarse recursivamente
            safe_dirs = []
            for d in dirs:
                # Omitir subdirectorios de cuarentena previas
                if d.startswith("_quarantine_"):
                    continue

                d_path = root_path / d
                # Filtrar enlaces simbólicos y junctions en Windows
                if is_symlink_or_junction(d_path):
                    if on_warning:
                        on_warning(f"Omitiendo enlace simbólico/junction de directorio: '{d_path}'")
                    continue

                safe_dirs.append(d)

            dirs[:] = safe_dirs

            # Procesar archivos regulares del directorio actual
            for f in files:
                file_path = root_path / f

                # Ignorar enlaces simbólicos a archivos
                if is_symlink_or_junction(file_path):
                    continue

                try:
                    if file_path.is_file():
                        yield file_path
                except (PermissionError, OSError) as e:
                    if on_warning:
                        on_warning(f"Permiso denegado al inspeccionar archivo '{file_path}': {e}")
                    continue

    except (PermissionError, OSError) as e:
        if on_warning:
            on_warning(f"Error accediendo al árbol de directorios en '{base_dir}': {e}")
        return

def scan_directory_for_duplicates(
    base_dir: Path,
    max_workers: int | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Callable[[int, int, str], None] | None = None,
    warning_callback: Callable[[str], None] | None = None
) -> tuple[dict[str, list[Path]], ScanSummary]:
    """
    Escanea recursivamente un directorio seguro y agrupa archivos por su hash SHA-256.

    Estrategia de rendimiento y hardening:
    1. Agrupación preliminar por tamaño de archivo (st_size) en O(1) de metadatos.
    2. Filtrado explícito de enlaces simbólicos y junctions de Windows (previene bucles infinitos).
    3. Hashing SHA-256 concurrente con número regulado de hilos para evitar saturación de descriptores (Too many open files).
    4. Manejo silencioso y robusto de PermissionError/OSError registrando advertencias.

    Args:
        base_dir: Directorio validado a auditar.
        max_workers: Número de hilos solicitados (regulado automáticamente a un rango seguro).
        chunk_size: Tamaño de bloque de lectura binaria (bytes).
        progress_callback: Callback opcional(procesados, total, archivo_actual).
        warning_callback: Callback opcional(mensaje_advertencia).

    Returns:
        Tupla con:
        - Diccionario de hashes duplicados: {sha256: [ruta1, ruta2, ...]} (len(paths) > 1)
        - Resumen estadístico ScanSummary
    """
    summary = ScanSummary(base_dir=base_dir)

    def log_warning(msg: str):
        summary.warnings.append(msg)
        if warning_callback:
            warning_callback(msg)

    # Paso 1: Mapeo preliminar por tamaño de archivo usando generador seguro
    size_map: dict[int, list[Path]] = {}
    for file_path in iter_directory_files(base_dir, on_warning=log_warning):
        summary.total_files_scanned += 1
        try:
            stat = file_path.stat(follow_symlinks=False)
            file_size = stat.st_size
            summary.total_bytes_scanned += file_size

            if file_size not in size_map:
                size_map[file_size] = []
            size_map[file_size].append(file_path)
        except (PermissionError, OSError) as e:
            summary.unreadable_files_count += 1
            log_warning(f"No se pudieron leer metadatos de '{file_path}': {e}")
            continue

    # Filtrar solo aquellos archivos cuyos tamaños colisionan con al menos otro archivo
    candidate_files: list[Path] = []
    for f_size, paths in size_map.items():
        if len(paths) > 1:
            candidate_files.extend(paths)

    total_candidates = len(candidate_files)
    if total_candidates == 0:
        return {}, summary

    # Paso 2: Cálculo concurrente de SHA-256 con regulación estricta de trabajadores
    safe_workers = get_safe_worker_count(max_workers)
    hash_map: dict[str, list[Path]] = {}

    def _process_candidate(fp: Path) -> tuple[str | None, Path]:
        res_hash = compute_file_hash(fp, chunk_size=chunk_size, on_error=log_warning)
        return res_hash, fp

    processed_count = 0
    with ThreadPoolExecutor(max_workers=safe_workers) as executor:
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
            
            redundant_count = len(paths) - 1
            recoverable_bytes += (single_file_size * redundant_count)
            total_dup_files += len(paths)

    summary.duplicate_groups_count = len(duplicates)
    summary.total_duplicate_files = total_dup_files
    summary.recoverable_bytes = recoverable_bytes

    return duplicates, summary
