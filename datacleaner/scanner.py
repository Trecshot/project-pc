"""
Motor de Escaneo y Detección de Duplicados de Máximo Rendimiento
DataCleaner CLI/GUI

Optimizaciones Integradas:
1. Caché de Estado Hashed (Stateful Caching en SQLite O(1)):
   Reutiliza hashes SHA-256 persistidos en .datacleaner.sqlite verificando (st_dev, st_ino, st_mtime, st_size).
2. Filtrado Instantáneo O(1) en RAM:
   Descarta archivos con st_size único inmediatamente en conjuntos nativos en C antes de tocar el disco.
3. Concurrencia Nativa con ThreadPoolExecutor:
   Lectura síncrona optimizada por bloques en hilos trabajadores nativos del sistema donde file.read y
   hashlib liberan el GIL en C, saturando el ancho de banda del bus de almacenamiento (SSD/NVMe).
4. Cancelación Cooperativa y Zero Doble-Lectura:
   Soporte para interrupción interactiva (cancel_event) y persistencia de firmas forenses (Magic Numbers).
"""

from pathlib import Path
import os
import asyncio
import threading
import logging
from dataclasses import dataclass, field
from typing import Callable, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed

from datacleaner.hasher import (
    compute_file_hash,
    compute_partial_hash,
    get_safe_worker_count,
    DEFAULT_CHUNK_SIZE,
)
from datacleaner.magic import analyze_file_signature, FileSignatureReport
from datacleaner.bloom import BloomFilter
from datacleaner.history import CleaningHistoryManager
from datacleaner.security import is_protected_dev_resource

logger = logging.getLogger(__name__)


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
    # Telemetría de Optimizaciones Avanzadas
    cache_hits: int = 0
    cache_misses: int = 0
    bloom_unique_discarded: int = 0
    size_unique_discarded: int = 0
    async_io_enabled: bool = False
    cancelled: bool = False
    # Telemetría de Integridad por Firmas Binarias (Magic Numbers)
    spoofed_extensions_count: int = 0
    signature_anomalies: list[dict] = field(default_factory=list)
    file_signatures: dict[str, FileSignatureReport] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


PROTECTED_DIR_NAMES = {
    ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "env",
    "$recycle.bin", "system volume information", "node_modules", "appdata",
    "site-packages", ".pytest_cache"
}


def is_symlink_or_junction(path: Path) -> bool:
    """Detecta si una ruta es un enlace simbólico o un reparse point (Junction en NTFS/Windows)."""
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
    """Generador perezoso que recorre el directorio base sin seguir enlaces simbólicos ni uniones."""
    try:
        for root, dirs, files in os.walk(base_dir, followlinks=False):
            root_path = Path(root)

            safe_dirs = []
            for d in dirs:
                d_lower = d.lower()
                if d.startswith("_quarantine_") or d_lower in PROTECTED_DIR_NAMES:
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

                # CORRECCIÓN CRÍTICA 1: Proteger archivos estructurales y entornos virtuales
                if is_protected_dev_resource(file_path):
                    continue

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
    warning_callback: Callable[[str], None] | None = None,
    use_cache: bool = True,
    history_manager: CleaningHistoryManager | None = None,
    cancel_event: threading.Event | None = None,
    bloom_filter: BloomFilter | None = None,
    include_empty_files: bool = False,
) -> tuple[dict[str, list[Path]], ScanSummary]:
    """
    Motor nativo de escaneo Multi-Stage de alto rendimiento:
    - Fase 1: Agrupación instantánea por st_size en memoria RAM con Filtro de Bloom (O(1)).
    - Fase 2: Fast-Hash en hilos de trabajo nativos (ThreadPoolExecutor) con consulta SQLite O(1).
    - Fase 3: SHA-256 criptográfico solo sobre colisiones confirmadas, liberando el GIL en C.
    - Soporta cancelación interactiva mediante cancel_event (MED-01).
    """
    summary = ScanSummary(base_dir=base_dir)
    hist_mgr = history_manager or (CleaningHistoryManager() if use_cache else None)

    def log_warning(msg: str):
        summary.warnings.append(msg)
        if warning_callback:
            warning_callback(msg)

    # =========================================================================
    # FASE 1: Recorrido O(1) en RAM + Detección de Hardlinks con Filtro de Bloom
    # =========================================================================
    bloom = bloom_filter or BloomFilter(expected_elements=1_000_000, false_positive_rate=0.005)
    pending_unique: dict[int, Path] = {}
    colliding_size_map: dict[int, list[Path]] = {}
    seen_inodes_per_size: dict[int, set[tuple[int, int]]] = {}

    for file_path in iter_directory_files(base_dir, on_warning=log_warning):
        if cancel_event and cancel_event.is_set():
            summary.cancelled = True
            log_warning("Auditoría cancelada por el usuario en Fase 1.")
            return {}, summary

        # CORRECCIÓN CRÍTICA 1: Proteger archivos estructurales y entornos virtuales
        if is_protected_dev_resource(file_path):
            continue

        try:
            stat = file_path.stat(follow_symlinks=False)
            file_size = stat.st_size

            # CORRECCIÓN CRÍTICA 2: Ignorar archivos de 0 bytes por defecto
            if file_size == 0 and not include_empty_files:
                continue

            summary.total_files_scanned += 1
            summary.total_bytes_scanned += file_size

            # Omitir archivos que ya comparten inodo físico (Hardlinks existentes)
            inode_key = (getattr(stat, "st_dev", 0), getattr(stat, "st_ino", 0))
            if inode_key[1] != 0:
                inodes_set = seen_inodes_per_size.setdefault(file_size, set())
                if inode_key in inodes_set:
                    summary.already_hardlinked_skipped += 1
                    continue
                inodes_set.add(inode_key)

            # Clasificación O(1) mediante Filtro de Bloom en RAM:
            # 1. Si file_size NO está en el filtro de Bloom (cero falsos negativos),
            #    es 100% seguro la primera vez que se observa. Se agrega al filtro y a pending_unique.
            if file_size not in bloom:
                bloom.add(file_size)
                pending_unique[file_size] = file_path
            else:
                # 2. El filtro de Bloom indica que el tamaño ya fue visto (potencial colisión).
                if file_size in pending_unique:
                    first_fp = pending_unique.pop(file_size)
                    colliding_size_map[file_size] = [first_fp, file_path]
                elif file_size in colliding_size_map:
                    colliding_size_map[file_size].append(file_path)
                else:
                    # Falso positivo infrecuente de Bloom (<0.5%): registrar como primer elemento real
                    pending_unique[file_size] = file_path

        except (PermissionError, OSError) as e:
            summary.unreadable_files_count += 1
            log_warning(f"No se pudieron leer metadatos de '{file_path}': {e}")
            continue

    unique_discarded = len(pending_unique)
    summary.size_unique_discarded = unique_discarded
    summary.bloom_unique_discarded = unique_discarded
    pending_unique.clear()

    candidate_files: list[Path] = []
    for f_size, paths in colliding_size_map.items():
        if len(paths) > 1:
            candidate_files.extend(paths)

    total_candidates = len(candidate_files)
    summary.size_collision_candidates = total_candidates
    if total_candidates == 0:
        return {}, summary

    workers = get_safe_worker_count(max_workers)

    # =========================================================================
    # FASE 2: Fast-Hash con Verificación en Caché SQLite (ThreadPoolExecutor)
    # =========================================================================
    partial_map: dict[tuple[int, str], list[Path]] = {}
    cached_sha_map: dict[Path, str] = {}
    new_cache_entries: list[dict] = []
    computed_partial_hashes: dict[Path, str] = {}

    cached_data = hist_mgr.load_cache_for_directory(base_dir) if hist_mgr and hasattr(hist_mgr, "load_cache_for_directory") else None

    def _worker_phase2(fp: Path) -> tuple[int, str | None, str | None, Path, bool]:
        try:
            st = fp.stat(follow_symlinks=False)
            f_size = st.st_size
            st_dev = getattr(st, "st_dev", 0)
            st_ino = getattr(st, "st_ino", 0)
            st_mtime = st.st_mtime
        except OSError:
            return 0, None, None, fp, False

        # Consulta en Caché de Estado O(1) en memoria (sin llamadas bloqueantes a SQLite)
        if cached_data:
            entry = None
            if st_ino and str(st_ino) != "0":
                entry = cached_data["by_inode"].get((str(st_dev), str(st_ino)))
            if not entry:
                norm_p = os.path.normcase(str(fp.resolve()))
                entry = cached_data["by_path"].get(norm_p) or cached_data["by_path"].get(str(fp.resolve()))
            if entry and abs(entry["mtime"] - st_mtime) < 1e-4 and entry["file_size"] == f_size:
                c_part = entry["partial_hash"]
                c_sha = entry["sha256_hash"]
                if c_sha and c_part and len(c_part) == 32:
                    return f_size, c_part, c_sha, fp, True
        elif hist_mgr:
            c_part, c_sha = hist_mgr.get_cached_file_hash(fp, st_dev, st_ino, st_mtime, f_size)
            if c_sha and c_part and len(c_part) == 32:
                return f_size, c_part, c_sha, fp, True

        p_hash = compute_partial_hash(fp, chunk_size=chunk_size, on_error=log_warning)
        return f_size, p_hash, None, fp, False

    p2_done = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_worker_phase2, fp): fp for fp in candidate_files}
        for future in as_completed(futures):
            if cancel_event and cancel_event.is_set():
                summary.cancelled = True
                for fut in futures:
                    fut.cancel()
                log_warning("Auditoría cancelada por el usuario en Fase 2.")
                return {}, summary

            try:
                f_size, p_hash, c_sha, f_path, is_cache_hit = future.result()
            except Exception as exc:
                summary.unreadable_files_count += 1
                log_warning(f"Error procesando Fast-Hash: {exc}")
                continue

            p2_done += 1
            summary.partial_hash_evaluated += 1

            if is_cache_hit:
                summary.cache_hits += 1
                if c_sha:
                    cached_sha_map[f_path] = c_sha
                if p_hash:
                    computed_partial_hashes[f_path] = p_hash
            else:
                summary.cache_misses += 1
                if p_hash:
                    computed_partial_hashes[f_path] = p_hash

            if progress_callback:
                pct_step = max(1, int((p2_done / total_candidates) * 40))
                progress_callback(pct_step, total_candidates, f"[Fase 2 Fast-Hash] {f_path.name}")

            if p_hash is not None:
                partial_map.setdefault((f_size, p_hash), []).append(f_path)
            else:
                summary.unreadable_files_count += 1

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
    # FASE 3: SHA-256 Completo en Hilos Nativos (Zero GIL Contention)
    # =========================================================================
    hash_map: dict[str, list[Path]] = {}

    def _worker_phase3(fp: Path) -> tuple[str | None, Path, dict | None]:
        if fp in cached_sha_map:
            return cached_sha_map[fp], fp, None

        res_hash = compute_file_hash(fp, chunk_size=chunk_size, on_error=log_warning)
        cache_entry = None
        if res_hash and hist_mgr:
            try:
                st = fp.stat(follow_symlinks=False)
                cache_entry = {
                    "file_path": str(fp.resolve()),
                    "device_id": getattr(st, "st_dev", 0),
                    "inode": getattr(st, "st_ino", 0),
                    "file_size": st.st_size,
                    "mtime": st.st_mtime,
                    "partial_hash": computed_partial_hashes.get(fp),
                    "sha256_hash": res_hash,
                }
            except OSError:
                pass
        return res_hash, fp, cache_entry

    p3_done = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures_p3 = {executor.submit(_worker_phase3, fp): fp for fp in phase2_survivors}
        for future in as_completed(futures_p3):
            if cancel_event and cancel_event.is_set():
                summary.cancelled = True
                for fut in futures_p3:
                    fut.cancel()
                log_warning("Auditoría cancelada por el usuario en Fase 3.")
                return {}, summary

            try:
                res_hash, f_path, c_entry = future.result()
            except Exception as exc:
                summary.unreadable_files_count += 1
                log_warning(f"Error procesando SHA-256: {exc}")
                continue

            p3_done += 1
            summary.full_hash_evaluated += 1

            if c_entry:
                new_cache_entries.append(c_entry)

            if progress_callback:
                pct_step = 40 + max(1, int((p3_done / total_phase3) * 60))
                progress_callback(pct_step, total_phase3, f"[Fase 3 SHA-256] {f_path.name}")

            if res_hash:
                hash_map.setdefault(res_hash, []).append(f_path)
            else:
                summary.unreadable_files_count += 1

    # Guardar en lote los nuevos hashes en la caché de SQLite
    if hist_mgr and new_cache_entries:
        try:
            hist_mgr.set_cached_hashes_batch(new_cache_entries)
        except Exception as e:
            logger.debug(f"Aviso guardando lote de hashes en SQLite: {e}")

    # Filtrar solo colisiones definitivas
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

    # Análisis forense de firmas binarias exclusivamente sobre duplicados confirmados
    for paths in duplicates.values():
        for dup_fp in paths:
            resolved_str = str(dup_fp.resolve())
            if resolved_str not in summary.file_signatures:
                sig_report = analyze_file_signature(dup_fp)
                summary.file_signatures[resolved_str] = sig_report
                if sig_report.is_anomaly:
                    summary.spoofed_extensions_count += 1
                    summary.signature_anomalies.append(sig_report.to_dict())
                    log_warning(sig_report.forensic_note)

    summary.duplicate_groups_count = len(duplicates)
    summary.total_duplicate_files = total_dup_files
    summary.recoverable_bytes = recoverable_bytes

    return duplicates, summary


async def scan_directory_async(
    base_dir: Path,
    max_workers: int | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Callable[[int, int, str], None] | None = None,
    warning_callback: Callable[[str], None] | None = None,
    use_cache: bool = True,
    history_manager: CleaningHistoryManager | None = None,
    cancel_event: threading.Event | None = None,
    include_empty_files: bool = False,
) -> tuple[dict[str, list[Path]], ScanSummary]:
    """
    Interfaz asíncrona compatible con AsyncIO:
    Delega la ejecución al motor de ThreadPoolExecutor nativo liberando el Event Loop.
    """
    return await asyncio.to_thread(
        scan_directory_for_duplicates,
        base_dir=base_dir,
        max_workers=max_workers,
        chunk_size=chunk_size,
        progress_callback=progress_callback,
        warning_callback=warning_callback,
        use_cache=use_cache,
        history_manager=history_manager,
        cancel_event=cancel_event,
        include_empty_files=include_empty_files,
    )
