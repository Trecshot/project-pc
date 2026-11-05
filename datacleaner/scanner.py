"""
Motor de Escaneo y Detección de Duplicados con Dispersión Escalonada (Multi-Stage Hashing)
DataCleaner CLI/GUI

Pipeline de evaluación en tres fases (O(1) -> O(k) -> O(n)):
- Fase 1 (O(1)): Agrupación por tamaño exacto (st_size) y detección de inodos compartidos (Hardlinks).
- Fase 2 (O(k)): Fast Hash parcial sobre el primer y último bloque de 64 KB para descartar falsos positivos de tamaño.
- Fase 3 (O(n)): SHA-256 criptográfico completo únicamente sobre colisiones de Fase 2 + Auditoría de Firmas Binarias (Magic Numbers).
"""

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Generator
import os

from datacleaner.hasher import (
    compute_file_hash,
    compute_partial_hash,
    get_safe_worker_count,
    DEFAULT_CHUNK_SIZE,
)
from datacleaner.magic import analyze_file_signature, FileSignatureReport


@dataclass
class ScanSummary:
    """Metadatos globales del proceso de auditoría y telemetría Multi-Stage."""
    base_dir: Path
    total_files_scanned: int = 0
    total_bytes_scanned: int = 0
    duplicate_groups_count: int = 0
    total_duplicate_files: int = 0
    recoverable_bytes: int = 0
    unreadable_files_count: int = 0
    # Telemetría del Pipeline Multi-Stage (O(1) -> O(k) -> O(n))
    size_collision_candidates: int = 0
    partial_hash_evaluated: int = 0
    partial_hash_discarded: int = 0
    full_hash_evaluated: int = 0
    already_hardlinked_skipped: int = 0
    # Telemetría de Integridad por Firmas Binarias (Magic Numbers)
    spoofed_extensions_count: int = 0
    signature_anomalies: list[dict] = field(default_factory=list)
    file_signatures: dict[str, FileSignatureReport] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def is_symlink_or_junction(path: Path) -> bool:
    """
    Detecta si una ruta es un enlace simbólico o una unión de directorios (Junction en NTFS/Windows).
    Previene recursión infinita y conteos duplicados.
    """
    try:
        if path.is_symlink() or os.path.islink(path):
            return True

        if hasattr(path, "is_junction") and path.is_junction():
            return True

        stat_result = path.stat(follow_symlinks=False)
        if hasattr(stat_result, "st_file_attributes"):
            FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
            if stat_result.st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                return True

        return False
    except (PermissionError, OSError):
        return True


def iter_directory_files(base_dir: Path, on_warning: Callable[[str], None] | None = None) -> Generator[Path, None, None]:
    """
    Generador perezoso que recorre el directorio base sin seguir enlaces simbólicos ni uniones.
    Usa os.walk con followlinks=False para máxima seguridad y rendimiento de memoria.
    """
    try:
        for root, dirs, files in os.walk(base_dir, followlinks=False):
            root_path = Path(root)

            safe_dirs = []
            for d in dirs:
                if d.startswith("_quarantine_"):
                    continue

                d_path = root_path / d
                if is_symlink_or_junction(d_path):
                    if on_warning:
                        on_warning(f"Omitiendo enlace simbólico/junction de directorio: '{d_path}'")
                    continue

                safe_dirs.append(d)

            dirs[:] = safe_dirs

            for f in files:
                file_path = root_path / f

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
    Escanea recursivamente un directorio seguro aplicando el Algoritmo de Dispersión Escalonada:
    - Fase 1 (O(1)): Agrupación por tamaño exacto en bytes (st_size) + filtro de inodos (Hardlinks).
    - Fase 2 (O(k)): Fast Hash parcial (primer y último chunk de 64 KB) para descartar falsas colisiones.
    - Fase 3 (O(n)): SHA-256 criptográfico completo solo cuando la Fase 2 colisiona + Magic Numbers.
    """
    summary = ScanSummary(base_dir=base_dir)

    def log_warning(msg: str):
        summary.warnings.append(msg)
        if warning_callback:
            warning_callback(msg)

    # =========================================================================
    # FASE 1 (O(1)): Agrupación por st_size y detección de Hardlinks existentes
    # =========================================================================
    size_map: dict[int, list[Path]] = {}
    seen_inodes_per_size: dict[int, set[tuple[int, int]]] = {}

    for file_path in iter_directory_files(base_dir, on_warning=log_warning):
        summary.total_files_scanned += 1
        try:
            stat = file_path.stat(follow_symlinks=False)
            file_size = stat.st_size
            summary.total_bytes_scanned += file_size

            # Auditoría forense de firma binaria (Magic Numbers) en archivos escaneados
            sig_report = analyze_file_signature(file_path)
            summary.file_signatures[str(file_path.resolve())] = sig_report
            if sig_report.is_anomaly:
                summary.spoofed_extensions_count += 1
                summary.signature_anomalies.append(sig_report.to_dict())
                log_warning(sig_report.forensic_note)

            # Si el archivo ya es un Hardlink apuntando a un inodo físico ya registrado,
            # no ocupa espacio físico adicional en disco: se contabiliza y omite de duplicados.
            inode_key = ( getattr(stat, "st_dev", 0), getattr(stat, "st_ino", 0) )
            if inode_key[1] != 0:
                inodes_set = seen_inodes_per_size.setdefault(file_size, set())
                if inode_key in inodes_set:
                    summary.already_hardlinked_skipped += 1
                    continue
                inodes_set.add(inode_key)

            size_map.setdefault(file_size, []).append(file_path)
        except (PermissionError, OSError) as e:
            summary.unreadable_files_count += 1
            log_warning(f"No se pudieron leer metadatos de '{file_path}': {e}")
            continue

    # Filtrar solo aquellos archivos cuyo st_size colisiona con al menos otro archivo
    phase1_candidates: list[tuple[int, Path]] = []
    for f_size, paths in size_map.items():
        if len(paths) > 1:
            for p in paths:
                phase1_candidates.append((f_size, p))

    total_phase1 = len(phase1_candidates)
    summary.size_collision_candidates = total_phase1
    if total_phase1 == 0:
        return {}, summary

    safe_workers = get_safe_worker_count(max_workers)

    # =========================================================================
    # FASE 2 (O(k)): Fast Hash Parcial (Primer y Último fragmento de 64 KB)
    # =========================================================================
    partial_map: dict[tuple[int, str], list[Path]] = {}

    def _run_phase2(item: tuple[int, Path]) -> tuple[int, str | None, Path]:
        f_size, fp = item
        p_hash = compute_partial_hash(fp, chunk_size=chunk_size, on_error=log_warning)
        return f_size, p_hash, fp

    with ThreadPoolExecutor(max_workers=safe_workers) as executor:
        futures_p2 = {executor.submit(_run_phase2, item): item for item in phase1_candidates}
        p2_done = 0
        for future in as_completed(futures_p2):
            p2_done += 1
            summary.partial_hash_evaluated += 1
            f_size, p_hash, f_path = future.result()

            if progress_callback:
                pct_step = max(1, int(p2_done * 0.4))
                progress_callback(pct_step, total_phase1, f"[Fase 2 Fast-Hash] {f_path.name}")

            if p_hash is not None:
                partial_map.setdefault((f_size, p_hash), []).append(f_path)
            else:
                summary.unreadable_files_count += 1

    # Filtrar solo los archivos cuya Fase 2 (Fast Hash de bordes 64 KB) colisionó
    phase2_survivors: list[Path] = []
    for (_f_size, _p_hash), paths in partial_map.items():
        if len(paths) > 1:
            phase2_survivors.extend(paths)
        else:
            summary.partial_hash_discarded += len(paths)

    total_phase3 = len(phase2_survivors)
    if total_phase3 == 0:
        return {}, summary

    # =========================================================================
    # FASE 3 (O(n)): SHA-256 Criptográfico Completo (solo sobrevivientes Fase 2)
    # =========================================================================
    hash_map: dict[str, list[Path]] = {}

    def _run_phase3(fp: Path) -> tuple[str | None, Path]:
        res_hash = compute_file_hash(fp, chunk_size=chunk_size, on_error=log_warning)
        return res_hash, fp

    processed_p3 = 0
    with ThreadPoolExecutor(max_workers=safe_workers) as executor:
        futures_p3 = {executor.submit(_run_phase3, fp): fp for fp in phase2_survivors}

        for future in as_completed(futures_p3):
            processed_p3 += 1
            summary.full_hash_evaluated += 1
            res_hash, f_path = future.result()

            if progress_callback:
                progress_callback(processed_p3, total_phase3, f_path.name)

            if res_hash:
                hash_map.setdefault(res_hash, []).append(f_path)
            else:
                summary.unreadable_files_count += 1

    # Filtrar para conservar únicamente hashes SHA-256 con más de 1 archivo (duplicados reales)
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
