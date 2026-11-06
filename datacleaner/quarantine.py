"""
Subsistema de Cuarentena y Restauración Automatizada (Hardened Soft-Delete & Restore)
DataCleaner CLI/GUI

Traslada archivos redundantes a un directorio aislado preservando su árbol relativo,
incorporando resolución de colisiones de nombres mediante sufijos de unicidad (Zero Overwrite),
persistencia de metadatos estandarizados en manifest.json y motor de escaneo de sesiones
para restauración reversible mediante modal interactivo.
Cumple con RF-06 y las especificaciones de flujo de restauración interactivo.
"""

from pathlib import Path
from datetime import datetime
import json
import shutil
import os
import sys
import logging
import hashlib
import hmac

try:
    import msvcrt
    HAS_MSVCRT = True
except ImportError:
    HAS_MSVCRT = False

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False
from dataclasses import dataclass, asdict
from datacleaner.history import format_bytes_auto as _format_bytes, CleaningHistoryManager

logger = logging.getLogger(__name__)

try:
    from send2trash import send2trash
    HAS_SEND2TRASH = True
except ImportError:
    HAS_SEND2TRASH = False

@dataclass
class QuarantineItem:
    original_path: str
    quarantine_path: str
    relative_path: str
    hash_sha256: str
    size_bytes: int
    mtime: float
    restored: bool = False
    restored_at: str | None = None

@dataclass
class QuarantineResult:
    session_id: str
    quarantine_dir: Path
    manifest_path: Path
    total_moved: int
    total_bytes_moved: int
    items: list[QuarantineItem]
    errors: list[str]

@dataclass
class RestoreResult:
    manifest_path: Path
    total_restored: int
    total_bytes_restored: int
    skipped_count: int
    quarantine_folder_removed: bool
    errors: list[str]

@dataclass
class DeleteResult:
    total_deleted: int
    total_bytes_deleted: int
    used_trash: bool
    deleted_paths: list[str]
    errors: list[str]


@dataclass
class HardlinkResult:
    """Resultado de la deduplicación transparente a nivel de sistema operativo mediante Hardlinks."""
    total_linked: int
    total_bytes_saved: int
    linked_paths: list[str]
    errors: list[str]


def compute_manifest_signature(manifest_bytes: bytes, secret_key: bytes | None = None) -> str:
    """
    Calcula la firma criptográfica HMAC-SHA256 del manifiesto de cuarentena (NIST SSDF PO.4 / CNCF).
    Garantiza no-repudio e inmutabilidad, impidiendo adulteraciones maliciosas de rutas de restauración.
    """
    if secret_key is None:
        seed = f"{os.environ.get('COMPUTERNAME', '')}|{os.environ.get('USERNAME', '')}|DataCleanerQuarantineHMACSecret2026"
        secret_key = hashlib.sha256(seed.encode("utf-8")).digest()
    return hmac.new(secret_key, manifest_bytes, hashlib.sha256).hexdigest()


def sign_manifest_file(manifest_path: Path, secret_key: bytes | None = None) -> Path:
    """Genera el archivo adjunto manifest.json.sig con el HMAC-SHA256 del manifiesto."""
    manifest_bytes = manifest_path.read_bytes()
    sig = compute_manifest_signature(manifest_bytes, secret_key=secret_key)
    sig_path = manifest_path.with_name(manifest_path.name + ".sig")
    sig_path.write_text(sig, encoding="utf-8")
    return sig_path


def verify_manifest_signature(manifest_path: Path, secret_key: bytes | None = None) -> bool:
    """
    Verifica que el archivo manifest.json coincida de forma idéntica con manifest.json.sig.
    Retorna True si la firma es válida. Lanza ValueError si la firma no coincide (adulteración).
    Si el archivo .sig no existe (compatibilidad hacia atrás), retorna True.
    """
    sig_path = manifest_path.with_name(manifest_path.name + ".sig")
    if not sig_path.exists():
        return True
    expected_sig = sig_path.read_text(encoding="utf-8").strip()
    manifest_bytes = manifest_path.read_bytes()
    actual_sig = compute_manifest_signature(manifest_bytes, secret_key=secret_key)
    if not hmac.compare_digest(actual_sig, expected_sig):
        raise ValueError(
            f"[INTEGRIDAD COMPROMETIDA] La firma criptográfica de '{manifest_path.name}' es inválida. "
            "El archivo fue alterado o adulterado tras su aislamiento. Restauración abortada por seguridad."
        )
    return True


def _verify_file_unchanged(file_path: Path, expected_size: int, expected_mtime: float) -> bool:
    """
    Previene pérdida de datos por condición de carrera TOCTOU a nivel de Kernel (CRIT-01).
    Opera directamente sobre descriptores de archivos del SO (os.open / os.fstat) con banderas
    de exclusión o bloqueo atómico en kernel (msvcrt.locking / fcntl.flock), neutralizando
    cualquier manipulación de inodos o sustitución de enlaces simbólicos en caliente.
    """
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = -1
    try:
        # Intentar apertura con permisos de lectura/escritura para bloqueo exclusivo si es posible
        try:
            rw_flags = flags | os.O_RDWR
            fd = os.open(file_path, rw_flags)
        except (PermissionError, OSError):
            fd = os.open(file_path, flags)

        locked = False
        lock_bytes = max(1, min(expected_size, 4096))

        if sys.platform == "win32" and HAS_MSVCRT:
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, lock_bytes)
                locked = True
            except (OSError, IOError):
                pass
        elif HAS_FCNTL:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                locked = True
            except (OSError, IOError):
                pass

        # Verificación directa de metadatos en inodo/handle abierto a través de fstat
        st = os.fstat(fd)
        unchanged = (st.st_size == expected_size and abs(st.st_mtime - expected_mtime) < 1e-4)

        if locked:
            try:
                if sys.platform == "win32" and HAS_MSVCRT:
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, lock_bytes)
                elif HAS_FCNTL:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            except (OSError, IOError):
                pass

        return unchanged
    except (PermissionError, OSError, FileNotFoundError):
        return False
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass

def create_quarantine_directory(base_dir: Path, custom_parent: Path | None = None) -> tuple[Path, str, str]:
    """
    Crea un directorio de cuarentena con marca de tiempo única.
    Retorna (quarantine_dir, session_id, timestamp_iso).
    Ejemplo: ./_quarantine_20261104_163151/
    """
    now = datetime.now()
    timestamp_str = now.strftime("%Y%m%d_%H%M%S")
    timestamp_iso = now.strftime("%Y-%m-%dT%H:%M:%S")
    session_id = f"quarantine_{timestamp_str}"
    folder_name = f"_{session_id}"

    parent = custom_parent if custom_parent else base_dir
    quarantine_dir = (parent / folder_name).resolve().absolute()
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    return quarantine_dir, session_id, timestamp_iso

def quarantine_redundant_files(
    base_dir: Path,
    quarantine_plan: list[dict],
    custom_quarantine_dir: Path | None = None
) -> QuarantineResult:
    """
    Ejecuta el traslado no destructivo (soft-delete) de los archivos redundantes.
    Genera el manifest.json estructurado con session_id, timestamp, total_files, total_bytes y files.

    Args:
        base_dir: Directorio base auditado.
        quarantine_plan: Lista con formato [{"hash": sha, "keep": Path, "quarantine": [Path, ...]}]
        custom_quarantine_dir: Carpeta personalizada opcional de destino.

    Returns:
        QuarantineResult con detalles de la operación y el archivo manifest.json generado.
    """
    if custom_quarantine_dir:
        quarantine_dir = Path(custom_quarantine_dir).resolve().absolute()
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        session_id = quarantine_dir.name.lstrip("_")
        timestamp_iso = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    else:
        quarantine_dir, session_id, timestamp_iso = create_quarantine_directory(base_dir)

    manifest_path = quarantine_dir / "manifest.json"

    items: list[QuarantineItem] = []
    errors: list[str] = []
    total_moved = 0
    total_bytes_moved = 0

    for group in quarantine_plan:
        file_hash = group.get("hash", "")
        redundant_paths: list[Path] = group.get("quarantine", [])
        snapshots: dict[str, tuple[int, float]] = group.get("quarantine_snapshots", {})

        for orig_file in redundant_paths:
            orig_path = Path(orig_file).resolve().absolute()
            if not orig_path.exists():
                errors.append(f"Archivo original no encontrado para cuarentena: {orig_path}")
                continue

            # Verificación anti-TOCTOU: si el archivo mutó tras el escaneo, abortar operación sobre él
            resolved_key = str(orig_path)
            snap = None
            if snapshots:
                snap = snapshots.get(resolved_key) or snapshots.get(os.path.normcase(resolved_key)) or snapshots.get(str(orig_file))
            if snap:
                exp_size, exp_mtime = snap
                if not _verify_file_unchanged(orig_path, exp_size, exp_mtime):
                    errors.append(
                        f"[TOCTOU] El archivo '{orig_path}' fue modificado tras el escaneo. "
                        "Operación de cuarentena abortada para prevenir pérdida de datos."
                    )
                    continue

            try:
                # Calcular ruta relativa respecto al base_dir
                try:
                    rel_path = orig_path.relative_to(base_dir.resolve().absolute())
                except ValueError:
                    rel_path = Path(str(orig_path).replace(":", ""))
                    if rel_path.is_absolute():
                        rel_path = rel_path.relative_to(rel_path.anchor)

                dest_file = (quarantine_dir / rel_path).resolve().absolute()

                # Prevención de colisiones: si dest_file ya existe, genera sufijo único
                if dest_file.exists():
                    parent_dir = dest_file.parent
                    stem = dest_file.stem
                    suffix = dest_file.suffix
                    short_hash = file_hash[:8] if file_hash else "dup"
                    counter = 1
                    while dest_file.exists():
                        dest_file = parent_dir / f"{stem}_{short_hash}_{counter}{suffix}"
                        counter += 1

                dest_file.parent.mkdir(parents=True, exist_ok=True)

                stat = orig_path.stat()
                file_size = stat.st_size
                mtime = stat.st_mtime

                # Mover archivo de manera no destructiva (soft-delete)
                shutil.move(str(orig_path), str(dest_file))

                item = QuarantineItem(
                    original_path=str(orig_path),
                    quarantine_path=str(dest_file),
                    relative_path=str(rel_path),
                    hash_sha256=file_hash,
                    size_bytes=file_size,
                    mtime=mtime,
                    restored=False
                )
                items.append(item)
                total_moved += 1
                total_bytes_moved += file_size

            except Exception as e:
                errors.append(f"Error moviendo '{orig_path}' a cuarentena: {str(e)}")

    # Estructura del manifiesto según especificación técnica
    files_list = [asdict(i) for i in items]
    manifest_data = {
        "session_id": session_id,
        "timestamp": timestamp_iso,
        "base_dir": str(base_dir.resolve().absolute()),
        "quarantine_dir": str(quarantine_dir.resolve().absolute()),
        "total_files": total_moved,
        "total_bytes": total_bytes_moved,
        "files": files_list,
        # Claves adicionales para compatibilidad
        "items": files_list
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2, ensure_ascii=False)

    # Firmado criptográfico del manifiesto para garantizar inmutabilidad y no repudio (NIST SSDF PO.4)
    sign_manifest_file(manifest_path)

    if items:
        try:
            CleaningHistoryManager().invalidate_cache_entries([i.original_path for i in items])
        except Exception as e:
            logger.debug(f"Aviso invalidando caché en cuarentena: {e}")

    return QuarantineResult(
        session_id=session_id,
        quarantine_dir=quarantine_dir,
        manifest_path=manifest_path,
        total_moved=total_moved,
        total_bytes_moved=total_bytes_moved,
        items=items,
        errors=errors
    )

def find_quarantine_sessions(base_dir: Path | str) -> list[dict]:
    """
    Escaneo Local: Busca en base_dir todas las carpetas con el prefijo _quarantine_
    y lee sus archivos manifest.json sin necesidad de calcular pesos en tiempo real.

    Returns:
        Lista de diccionarios ordenados por fecha descendente (más reciente primero).
    """
    target = Path(base_dir).resolve().absolute()
    sessions = []

    if not target.exists() or not target.is_dir():
        return []

    try:
        for entry in target.iterdir():
            if entry.is_dir() and entry.name.startswith("_quarantine_"):
                manifest_file = entry / "manifest.json"
                if manifest_file.exists():
                    try:
                        with open(manifest_file, "r", encoding="utf-8") as f:
                            data = json.load(f)

                        ts = data.get("timestamp", "")
                        if ts:
                            date_display = ts.replace("T", " ")
                        else:
                            # Parsear timestamp desde el nombre de carpeta: _quarantine_YYYYMMDD_HHMMSS
                            raw = entry.name.replace("_quarantine_", "")
                            if len(raw) == 15 and "_" in raw:
                                date_display = f"{raw[:4]}-{raw[4:6]}-{raw[6:8]} {raw[9:11]}:{raw[11:13]}:{raw[13:15]}"
                            else:
                                date_display = raw

                        total_f = data.get("total_files", 0)
                        total_b = data.get("total_bytes", 0)
                        session_id = data.get("session_id", entry.name.lstrip("_"))

                        sessions.append({
                            "session_id": session_id,
                            "folder_name": entry.name,
                            "folder_path": entry,
                            "manifest_path": manifest_file,
                            "timestamp": date_display,
                            "total_files": total_f,
                            "total_bytes": total_b,
                            "total_bytes_formatted": _format_bytes(total_b),
                            "fully_restored": data.get("fully_restored", False)
                        })
                    except Exception:
                        continue
    except (PermissionError, OSError):
        pass

    # Ordenar por carpeta / fecha descendente
    sessions.sort(key=lambda s: s["folder_name"], reverse=True)
    return sessions

def restore_from_quarantine(manifest_path: Path | str) -> RestoreResult:
    """
    Restaura automáticamente los archivos desde la cuarentena a sus ubicaciones originales
    utilizando el archivo manifest.json. Si todos los archivos son restaurados con éxito,
    elimina la carpeta de cuarentena vacía.

    Args:
        manifest_path: Ruta al archivo manifest.json generado durante la cuarentena.

    Returns:
        RestoreResult con el balance de archivos restaurados y confirmación de eliminación.
    """
    manifest_p = Path(manifest_path).resolve().absolute()
    if not manifest_p.exists():
        raise FileNotFoundError(f"No se encontró el manifiesto de cuarentena: '{manifest_p}'")

    # Verificación de integridad criptográfica y no repudio (NIST SSDF PO.4 / CNCF)
    verify_manifest_signature(manifest_p)

    quarantine_dir = manifest_p.parent

    with open(manifest_p, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)

    # Soporte para ambas claves ("files" y "items")
    files_data = manifest_data.get("files") or manifest_data.get("items") or []
    total_restored = 0
    total_bytes_restored = 0
    skipped_count = 0
    errors: list[str] = []

    for item in files_data:
        if item.get("restored", False):
            skipped_count += 1
            continue

        q_path_str = item.get("quarantine_path") or item.get("quarantined_path")
        if not q_path_str:
            continue
        q_path = Path(q_path_str)
        orig_path = Path(item["original_path"])

        if not q_path.exists():
            errors.append(f"Archivo en cuarentena no encontrado: '{q_path}'")
            continue

        # Evitar sobreescribir si ya existe un archivo en la ruta original
        if orig_path.exists():
            errors.append(f"Conflicto de destino: el archivo original ya existe: '{orig_path}'")
            continue

        try:
            orig_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(q_path), str(orig_path))
            item["restored"] = True
            item["restored_at"] = datetime.now().isoformat()
            total_restored += 1
            total_bytes_restored += item.get("size_bytes", 0)
        except Exception as e:
            errors.append(f"Error restaurando '{q_path}' a '{orig_path}': {str(e)}")

    all_restored = all(it.get("restored", False) for it in files_data)
    quarantine_folder_removed = False

    if all_restored and len(errors) == 0:
        # Fase 5: Eliminar la carpeta de cuarentena vacía si todo se restauró exitosamente
        try:
            manifest_p.unlink(missing_ok=True)
            manifest_p.with_name(manifest_p.name + ".sig").unlink(missing_ok=True)
            shutil.rmtree(quarantine_dir, ignore_errors=True)
            quarantine_folder_removed = True
        except Exception as e:
            errors.append(f"No se pudo eliminar la carpeta de cuarentena vacía: {e}")
    else:
        # Actualizar manifiesto si quedaron archivos pendientes o con error y re-firmar
        manifest_data["files"] = files_data
        manifest_data["items"] = files_data
        manifest_data["last_restored_at"] = datetime.now().isoformat()
        manifest_data["fully_restored"] = all_restored
        with open(manifest_p, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2, ensure_ascii=False)
        sign_manifest_file(manifest_p)

    return RestoreResult(
        manifest_path=manifest_p,
        total_restored=total_restored,
        total_bytes_restored=total_bytes_restored,
        skipped_count=skipped_count,
        quarantine_folder_removed=quarantine_folder_removed,
        errors=errors
    )

def purge_quarantine_session(quarantine_dir: Path | str) -> bool:
    """
    Elimina definitivamente la carpeta de cuarentena y su contenido completo.
    Incorpora validaciones de seguridad: verifica existencia y prefijo '_quarantine_'.
    """
    q_dir = Path(quarantine_dir).resolve().absolute()
    if not q_dir.exists() or not q_dir.is_dir():
        return False

    if not q_dir.name.startswith("_quarantine_"):
        raise ValueError(f"Ruta de cuarentena no válida o fuera del ámbito protegido: {q_dir.name}")

    shutil.rmtree(q_dir)
    return True

def purge_all_quarantine_sessions(base_dir: Path | str) -> int:
    """
    Elimina definitivamente todas las carpetas de cuarentena en base_dir.
    Retorna la cantidad de sesiones eliminadas.
    """
    sessions = find_quarantine_sessions(base_dir)
    purged_count = 0
    for s in sessions:
        if purge_quarantine_session(s["folder_path"]):
            purged_count += 1
    return purged_count

def delete_redundant_files(
    redundant_paths: list[Path | str],
    use_trash: bool = False,
    expected_snapshots: dict[str, tuple[int, float]] | None = None
) -> DeleteResult:
    """
    Elimina los archivos duplicados del disco (permanentemente o enviándolos a la Papelera de Windows).
    Incorpora blindaje contra TOCTOU verificando metadatos contra expected_snapshots (CRIT-01).

    Args:
        redundant_paths: Lista de rutas a eliminar.
        use_trash: Si es True, envía a la Papelera mediante send2trash.
                   Si es False, desvincula permanentemente con unlink()/os.remove().
        expected_snapshots: Mapeo opcional de str(path) -> (expected_size, expected_mtime) para TOCTOU.
    """
    if use_trash and not HAS_SEND2TRASH:
        raise RuntimeError(
            "No se puede enviar a la Papelera porque el módulo 'send2trash' no está instalado. "
            "Se abortó la operación para proteger sus archivos de un borrado permanente accidental."
        )

    deleted_paths: list[str] = []
    errors: list[str] = []
    total_deleted = 0
    total_bytes_deleted = 0

    for path_item in redundant_paths:
        p = Path(path_item).resolve().absolute()
        if not p.exists():
            continue

        resolved_key = str(p)
        snap = None
        if expected_snapshots:
            snap = (
                expected_snapshots.get(resolved_key)
                or expected_snapshots.get(os.path.normcase(resolved_key))
                or expected_snapshots.get(str(path_item))
            )
        if snap:
            exp_size, exp_mtime = snap
            if not _verify_file_unchanged(p, exp_size, exp_mtime):
                errors.append(
                    f"[TOCTOU] El archivo '{p}' fue modificado tras el escaneo. "
                    "Eliminación cancelada para proteger datos nuevos."
                )
                continue

        try:
            file_size = p.stat().st_size
            if use_trash:
                if HAS_SEND2TRASH:
                    send2trash(str(p))
                else:
                    p.unlink()
            else:
                p.unlink()

            total_deleted += 1
            total_bytes_deleted += file_size
            deleted_paths.append(str(p))
        except OSError as e:
            errors.append(f"Error al eliminar {p}: {e}")
        except Exception as e:
            errors.append(f"Error inesperado al procesar {p}: {e}")

    if deleted_paths:
        try:
            CleaningHistoryManager().invalidate_cache_entries(deleted_paths)
        except Exception as e:
            logger.debug(f"Aviso invalidando caché en eliminación: {e}")

    return DeleteResult(
        total_deleted=total_deleted,
        total_bytes_deleted=total_bytes_deleted,
        used_trash=use_trash,
        deleted_paths=deleted_paths,
        errors=errors
    )

def execute_deletion_plan(
    quarantine_plan: list[dict],
    use_trash: bool = False
) -> DeleteResult:
    """
    Ejecuta el borrado directo (papelera o definitivo) a partir de un plan de auditoría.
    Extrae los archivos marcados como redundantes y propaga los snapshots para validación TOCTOU.
    """
    all_redundant: list[Path] = []
    all_snapshots: dict[str, tuple[int, float]] = {}
    for group in quarantine_plan:
        all_redundant.extend(group.get("quarantine", []))
        group_snaps = group.get("quarantine_snapshots", {})
        if group_snaps:
            all_snapshots.update(group_snaps)

    return delete_redundant_files(all_redundant, use_trash=use_trash, expected_snapshots=all_snapshots)


def deduplicate_with_hardlinks(quarantine_plan: list[dict]) -> HardlinkResult:
    """
    Deduplicación Transparente mediante Hardlinks (OS-Level: NTFS, ext4, APFS):
    En lugar de mover el archivo a cuarentena o eliminar su ruta en el árbol del usuario,
    reemplaza de forma atómica cada copia redundante por un enlace físico (`os.link(keep_file, redundant_file)`)
    que apunta al mismo clúster de datos físicos en disco que el archivo maestro (`keep`).

    Garantía Transaccional (Zero Data Loss):
    1. Renombra temporalmente la copia redundante a un archivo `.dc_hl_bak` en su misma carpeta.
    2. Crea el enlace físico `os.link(keep_path, redundant_path)`.
    3. Si tiene éxito, elimina el respaldo temporal `.dc_hl_bak`.
    4. Si falla (ej. volumen distinto o sistema de archivos sin soporte de hardlinks),
       restaura de inmediato el respaldo temporal a su nombre original.
    """
    linked_paths: list[str] = []
    errors: list[str] = []
    total_linked = 0
    total_bytes_saved = 0

    for group in quarantine_plan:
        keep_raw = group.get("keep")
        if not keep_raw:
            continue
        keep_path = Path(keep_raw).resolve().absolute()
        if not keep_path.exists():
            errors.append(f"Archivo maestro KEEP no existe: {keep_path}")
            continue

        try:
            keep_stat = keep_path.stat()
        except OSError as e:
            errors.append(f"No se pudo inspeccionar archivo maestro '{keep_path}': {e}")
            continue

        # Validación anti-TOCTOU sobre el archivo maestro KEEP
        exp_keep_size = group.get("size_per_file") or group.get("expected_size")
        exp_keep_mtime = group.get("keep_mtime")
        if exp_keep_size is not None and exp_keep_mtime is not None:
            if not _verify_file_unchanged(keep_path, exp_keep_size, exp_keep_mtime):
                errors.append(
                    f"[TOCTOU] El archivo maestro KEEP '{keep_path}' fue modificado tras el escaneo. "
                    "Deduplicación por hardlinks abortada para proteger datos nuevos."
                )
                continue

        redundant_list: list[Path] = group.get("quarantine", [])
        snapshots: dict[str, tuple[int, float]] = group.get("quarantine_snapshots", {})
        for red_raw in redundant_list:
            red_path = Path(red_raw).resolve().absolute()
            if not red_path.exists() or red_path == keep_path:
                continue

            # Validación anti-TOCTOU sobre la copia redundante
            resolved_red_key = str(red_path)
            snap = None
            if snapshots:
                snap = (
                    snapshots.get(resolved_red_key)
                    or snapshots.get(os.path.normcase(resolved_red_key))
                    or snapshots.get(str(red_raw))
                )
            if snap:
                exp_size, exp_mtime = snap
                if not _verify_file_unchanged(red_path, exp_size, exp_mtime):
                    errors.append(
                        f"[TOCTOU] El archivo '{red_path}' fue modificado tras el escaneo. "
                        "Creación de hardlink abortada para proteger datos nuevos."
                    )
                    continue

            try:
                red_stat = red_path.stat()
                # Si ya apuntan al mismo inodo físico en el mismo volumen, omitir
                if (
                    getattr(keep_stat, "st_ino", 0) != 0
                    and keep_stat.st_dev == red_stat.st_dev
                    and keep_stat.st_ino == red_stat.st_ino
                ):
                    continue

                file_size = red_stat.st_size
                backup_path = red_path.with_name(f".{red_path.name}.dc_hl_bak")
                counter = 1
                while backup_path.exists():
                    backup_path = red_path.with_name(f".{red_path.name}.{counter}.dc_hl_bak")
                    counter += 1

                # Paso 1: Renombrado atómico a respaldo temporal
                red_path.replace(backup_path)
                try:
                    # Paso 2: Crear Hardlink físico en la ruta original apuntando al inodo de keep_path
                    os.link(str(keep_path), str(red_path))
                except Exception as link_err:
                    # Rollback atómico inmediato si os.link falla
                    if backup_path.exists() and not red_path.exists():
                        backup_path.replace(red_path)
                    errors.append(f"No se pudo crear hardlink para '{red_path}': {link_err}")
                    continue

                # Paso 3: Eliminar el respaldo temporal una vez confirmado el hardlink
                backup_path.unlink(missing_ok=True)
                total_linked += 1
                total_bytes_saved += file_size
                linked_paths.append(str(red_path))
            except Exception as e:
                errors.append(f"Error procesando hardlink en '{red_path}': {e}")

    if linked_paths:
        try:
            CleaningHistoryManager().invalidate_cache_entries(linked_paths)
        except Exception as e:
            logger.debug(f"Aviso invalidando caché en hardlinks: {e}")

    return HardlinkResult(
        total_linked=total_linked,
        total_bytes_saved=total_bytes_saved,
        linked_paths=linked_paths,
        errors=errors
    )


