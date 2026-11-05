"""
Motor de Escaneo y Detección de Duplicados de Máximo Rendimiento
DataCleaner CLI/GUI

Mejoras Arquitectónicas Integradas:
1. Caché de Estado Hashed (Stateful Caching en SQLite O(1)):
   Reutiliza hashes SHA-256 persistidos en .datacleaner.sqlite verificando (st_dev, st_ino, st_mtime, st_size).
2. Filtro de Bloom Probabilístico en RAM:
   Descarta archivos con st_size único inmediatamente antes de asignar estructuras en memoria.
3. E/S Asíncrona (AsyncIO + aiofiles):
   Non-blocking I/O con Event Loop y Semaphore regulado para saturar buses de alta velocidad (NVMe/SSD).
"""

from pathlib import Path
import asyncio
import os
from dataclasses import dataclass, field
from typing import Callable, Generator

from datacleaner.hasher import (
    compute_file_hash,
    compute_partial_hash,
    compute_file_hash_async,
    compute_partial_hash_async,
    get_safe_worker_count,
    DEFAULT_CHUNK_SIZE,
)
from datacleaner.magic import analyze_file_signature, FileSignatureReport
from datacleaner.bloom import BloomFilter
from datacleaner.history import CleaningHistoryManager


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
    async_io_enabled: bool = True
    # Telemetría de Integridad por Firmas Binarias (Magic Numbers)
    spoofed_extensions_count: int = 0
    signature_anomalies: list[dict] = field(default_factory=list)
    file_signatures: dict[str, FileSignatureReport] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


PROTECTED_DIR_NAMES = {
    ".git", ".svn", ".hg", "__pycache__", ".venv", "venv",
    "$recycle.bin", "system volume information", "node_modules", "appdata"
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


async def scan_directory_async(
    base_dir: Path,
    max_workers: int | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Callable[[int, int, str], None] | None = None,
    warning_callback: Callable[[str], None] | None = None,
    use_cache: bool = True,
    history_manager: CleaningHistoryManager | None = None
) -> tuple[dict[str, list[Path]], ScanSummary]:
    """
    Motor asíncrono de escaneo con Event Loop no bloqueante (AsyncIO + aiofiles):
    - Filtrado de tamaños únicos en RAM con complejidad O(1) y huella mínima.
    - Caché SQLite transaccional pre-cargada en memoria para omitir I/O sin bloquear el loop.
    - Concurrencia masiva regulada por asyncio.Semaphore.
    """
    summary = ScanSummary(base_dir=base_dir)
    hist_mgr = history_manager or (CleaningHistoryManager() if use_cache else None)

    def log_warning(msg: str):
        summary.warnings.append(msg)
        if warning_callback:
            warning_callback(msg)

    # =========================================================================
    # FASE 1: Recorrido O(1) en RAM + Detección de Hardlinks (Zero Disk Reads)
    # =========================================================================
    seen_sizes: set[int] = set()
    pending_unique: dict[int, Path] = {}
    colliding_size_map: dict[int, list[Path]] = {}
    seen_inodes_per_size: dict[int, set[tuple[int, int]]] = {}

    for file_path in iter_directory_files(base_dir, on_warning=log_warning):
        summary.total_files_scanned += 1
        try:
            stat = file_path.stat(follow_symlinks=False)
            file_size = stat.st_size
            summary.total_bytes_scanned += file_size

            # Omitir archivos que ya comparten inodo físico (Hardlinks existentes)
            inode_key = (getattr(stat, "st_dev", 0), getattr(stat, "st_ino", 0))
            if inode_key[1] != 0:
                inodes_set = seen_inodes_per_size.setdefault(file_size, set())
                if inode_key in inodes_set:
                    summary.already_hardlinked_skipped += 1
                    continue
                inodes_set.add(inode_key)

            # Clasificación O(1): Si el tamaño nunca se ha visto, se reserva en pending_unique.
            # Solo si aparece otro archivo con el mismo tamaño se promueve a colliding_size_map.
            if file_size not in seen_sizes:
                seen_sizes.add(file_size)
                pending_unique[file_size] = file_path
            else:
                if file_size in pending_unique:
                    first_fp = pending_unique.pop(file_size)
                    colliding_size_map[file_size] = [first_fp, file_path]
                elif file_size in colliding_size_map:
                    colliding_size_map[file_size].append(file_path)

        except (PermissionError, OSError) as e:
            summary.unreadable_files_count += 1
            log_warning(f"No se pudieron leer metadatos de '{file_path}': {e}")
            continue

    summary.bloom_unique_discarded = len(pending_unique)
    pending_unique.clear()
    seen_sizes.clear()

    candidate_files: list[Path] = []
    for f_size, paths in colliding_size_map.items():
        if len(paths) > 1:
            candidate_files.extend(paths)

    total_candidates = len(candidate_files)
    summary.size_collision_candidates = total_candidates
    if total_candidates == 0:
        return {}, summary

    # Semáforo para controlar descriptores abiertos concurrentes sin saturar el SO
    safe_concurrency = max(4, min(get_safe_worker_count(max_workers) * 8, 128))
    io_semaphore = asyncio.Semaphore(safe_concurrency)

    # =========================================================================
    # FASE 2: Fast-Hash Asíncrono con Verificación en Caché SQLite
    # =========================================================================
    partial_map: dict[tuple[int, str], list[Path]] = {}
    cached_sha_map: dict[Path, str] = {}
    new_cache_entries: list[dict] = []
    computed_partial_hashes: dict[Path, str] = {}

    # Pre-carga de caché en lote en memoria para búsquedas O(1) sin bloquear el Event Loop
    cached_data = hist_mgr.load_cache_for_directory(base_dir) if hist_mgr and hasattr(hist_mgr, "load_cache_for_directory") else None

    async def _async_phase2(fp: Path) -> tuple[int, str | None, Path]:
        async with io_semaphore:
            try:
                st = fp.stat(follow_symlinks=False)
                f_size = st.st_size
                st_dev = getattr(st, "st_dev", 0)
                st_ino = getattr(st, "st_ino", 0)
                st_mtime = st.st_mtime
            except OSError:
                return 0, None, fp

            # 1. Consulta en Caché de Estado O(1) en memoria (sin llamadas bloqueantes a SQLite)
            if cached_data:
                entry = None
                if st_ino and str(st_ino) != "0":
                    entry = cached_data["by_inode"].get((str(st_dev), str(st_ino)))
                if not entry:
                    entry = cached_data["by_path"].get(str(fp.resolve()))
                if entry and abs(entry["mtime"] - st_mtime) < 1e-4 and entry["file_size"] == f_size:
                    c_part = entry["partial_hash"]
                    c_sha = entry["sha256_hash"]
                    if c_sha and c_part and len(c_part) == 32:
                        summary.cache_hits += 1
                        cached_sha_map[fp] = c_sha
                        computed_partial_hashes[fp] = c_part
                        return f_size, c_part, fp
            elif hist_mgr:
                c_part, c_sha = hist_mgr.get_cached_file_hash(fp, st_dev, st_ino, st_mtime, f_size)
                if c_sha and c_part and len(c_part) == 32:
                    summary.cache_hits += 1
                    cached_sha_map[fp] = c_sha
                    computed_partial_hashes[fp] = c_part
                    return f_size, c_part, fp

            summary.cache_misses += 1
            # 2. Lectura Asíncrona con aiofiles (primer y último chunk 64 KB)
            p_hash = await compute_partial_hash_async(fp, chunk_size=chunk_size, on_error=log_warning)
            if p_hash:
                computed_partial_hashes[fp] = p_hash
            return f_size, p_hash, fp

    p2_tasks = [_async_phase2(fp) for fp in candidate_files]
    p2_done = 0
    for coro in asyncio.as_completed(p2_tasks):
        f_size, p_hash, f_path = await coro
        p2_done += 1
        summary.partial_hash_evaluated += 1

        if progress_callback:
            pct_step = max(1, int(p2_done * 0.4))
            progress_callback(pct_step, total_candidates, f"[Fase 2 Fast-Hash Async] {f_path.name}")

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
    # FASE 3: SHA-256 Asíncrono Completo + Actualización de Caché
    # =========================================================================
    hash_map: dict[str, list[Path]] = {}

    async def _async_phase3(fp: Path) -> tuple[str | None, Path]:
        # Si ya teníamos el SHA-256 desde la caché en Fase 2, lo retornamos inmediatamente
        if fp in cached_sha_map:
            return cached_sha_map[fp], fp

        async with io_semaphore:
            res_hash = await compute_file_hash_async(fp, chunk_size=chunk_size, on_error=log_warning)
            if res_hash and hist_mgr:
                try:
                    st = fp.stat(follow_symlinks=False)
                    new_cache_entries.append({
                        "file_path": str(fp.resolve()),
                        "device_id": getattr(st, "st_dev", 0),
                        "inode": getattr(st, "st_ino", 0),
                        "file_size": st.st_size,
                        "mtime": st.st_mtime,
                        "partial_hash": computed_partial_hashes.get(fp),
                        "sha256_hash": res_hash,
                    })
                except OSError:
                    pass
            return res_hash, fp

    p3_tasks = [_async_phase3(fp) for fp in phase2_survivors]
    p3_done = 0
    for coro in asyncio.as_completed(p3_tasks):
        res_hash, f_path = await coro
        p3_done += 1
        summary.full_hash_evaluated += 1

        if progress_callback:
            progress_callback(p3_done, total_phase3, f"[Fase 3 Async SHA-256] {f_path.name}")

        if res_hash:
            hash_map.setdefault(res_hash, []).append(f_path)
        else:
            summary.unreadable_files_count += 1

    # Guardar en lote los nuevos hashes en la caché de SQLite
    if hist_mgr and new_cache_entries:
        try:
            hist_mgr.set_cached_hashes_batch(new_cache_entries)
        except Exception:
            pass

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


def scan_directory_for_duplicates(
    base_dir: Path,
    max_workers: int | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Callable[[int, int, str], None] | None = None,
    warning_callback: Callable[[str], None] | None = None,
    use_cache: bool = True,
    history_manager: CleaningHistoryManager | None = None
) -> tuple[dict[str, list[Path]], ScanSummary]:
    """
    Punto de entrada síncrono compatible con GUI, CLI y pruebas:
    Ejecuta el pipeline asíncrono sobre el Event Loop de Python sin sobrecarga del GIL.
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    if loop.is_running():
        # Si ya se encuentra dentro de un loop en ejecución (ej. entorno embebido),
        # ejecutamos la corrutina en un hilo auxiliar para no bloquear el loop principal.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                asyncio.run,
                scan_directory_async(
                    base_dir=base_dir,
                    max_workers=max_workers,
                    chunk_size=chunk_size,
                    progress_callback=progress_callback,
                    warning_callback=warning_callback,
                    use_cache=use_cache,
                    history_manager=history_manager
                )
            )
            return future.result()
    else:
        return loop.run_until_complete(
            scan_directory_async(
                base_dir=base_dir,
                max_workers=max_workers,
                chunk_size=chunk_size,
                progress_callback=progress_callback,
                warning_callback=warning_callback,
                use_cache=use_cache,
                history_manager=history_manager
            )
        )
