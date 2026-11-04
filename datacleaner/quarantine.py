"""
Subsistema de Cuarentena y Restauración Automatizada (Soft-Delete & Restore)
DataCleaner CLI/GUI

Traslada archivos redundantes a un directorio aislado preservando su árbol relativo
y generando un manifiesto JSON reversible para restauración inmediata (RF-06 y Sección 7).
"""

from pathlib import Path
from datetime import datetime
import json
import shutil
import os
from dataclasses import dataclass, asdict

@dataclass
class QuarantineItem:
    original_path: str
    quarantined_path: str
    relative_path: str
    hash_sha256: str
    size_bytes: int
    mtime: float
    restored: bool = False
    restored_at: str | None = None

@dataclass
class QuarantineResult:
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
    errors: list[str]

def create_quarantine_directory(base_dir: Path, custom_parent: Path | None = None) -> Path:
    """
    Crea un directorio de cuarentena con marca de tiempo única.
    Ejemplo: ./_quarantine_20261104_154500/
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = f"_quarantine_{timestamp}"
    parent = custom_parent if custom_parent else base_dir
    quarantine_dir = (parent / folder_name).resolve()
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    return quarantine_dir

def quarantine_redundant_files(
    base_dir: Path,
    quarantine_plan: list[dict],
    custom_quarantine_dir: Path | None = None
) -> QuarantineResult:
    """
    Ejecuta el traslado no destructivo (soft-delete) de los archivos redundantemente detectados.

    Args:
        base_dir: Directorio base auditado.
        quarantine_plan: Lista de diccionarios con formato:
                         [{"hash": sha, "keep": Path, "quarantine": [Path, ...], "size": bytes}]
        custom_quarantine_dir: Carpeta personalizada de destino o None para generar una en base_dir.

    Returns:
        QuarantineResult con detalles de la operación y el archivo manifest.json generado.
    """
    quarantine_dir = custom_quarantine_dir or create_quarantine_directory(base_dir)
    manifest_path = quarantine_dir / "manifest.json"

    items: list[QuarantineItem] = []
    errors: list[str] = []
    total_moved = 0
    total_bytes_moved = 0

    for group in quarantine_plan:
        file_hash = group.get("hash", "")
        redundant_paths: list[Path] = group.get("quarantine", [])

        for orig_file in redundant_paths:
            orig_path = Path(orig_file).resolve()
            if not orig_path.exists():
                errors.append(f"Archivo original no encontrado para cuarentena: {orig_path}")
                continue

            try:
                # Calcular ruta relativa respecto al base_dir
                try:
                    rel_path = orig_path.relative_to(base_dir)
                except ValueError:
                    # En caso de estar en una raíz diferente, se replica la ruta sin los dos puntos
                    rel_path = Path(str(orig_path).replace(":", ""))
                    if rel_path.is_absolute():
                        rel_path = rel_path.relative_to(rel_path.anchor)

                dest_file = quarantine_dir / rel_path
                dest_file.parent.mkdir(parents=True, exist_ok=True)

                stat = orig_path.stat()
                file_size = stat.st_size
                mtime = stat.st_mtime

                # Mover archivo de manera no destructiva (soft-delete)
                shutil.move(str(orig_path), str(dest_file))

                item = QuarantineItem(
                    original_path=str(orig_path),
                    quarantined_path=str(dest_file),
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

    # Guardar manifiesto de estado en formato JSON
    manifest_data = {
        "format_version": "1.0",
        "timestamp": datetime.now().isoformat(),
        "base_dir": str(base_dir.resolve()),
        "quarantine_dir": str(quarantine_dir.resolve()),
        "total_files": total_moved,
        "total_bytes": total_bytes_moved,
        "items": [asdict(i) for i in items]
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2, ensure_ascii=False)

    return QuarantineResult(
        quarantine_dir=quarantine_dir,
        manifest_path=manifest_path,
        total_moved=total_moved,
        total_bytes_moved=total_bytes_moved,
        items=items,
        errors=errors
    )

def restore_from_quarantine(manifest_path: Path | str) -> RestoreResult:
    """
    Restaura automáticamente los archivos desde la cuarentena a sus ubicaciones originales
    utilizando el archivo manifest.json.

    Args:
        manifest_path: Ruta al archivo manifest.json generado durante la cuarentena.

    Returns:
        RestoreResult con el balance de archivos restaurados.
    """
    manifest_p = Path(manifest_path).resolve()
    if not manifest_p.exists():
        raise FileNotFoundError(f"No se encontró el manifiesto de cuarentena: '{manifest_p}'")

    with open(manifest_p, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)

    items_data = manifest_data.get("items", [])
    total_restored = 0
    total_bytes_restored = 0
    skipped_count = 0
    errors: list[str] = []

    for item in items_data:
        if item.get("restored", False):
            skipped_count += 1
            continue

        q_path = Path(item["quarantined_path"])
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

    # Guardar manifiesto actualizado
    manifest_data["items"] = items_data
    manifest_data["last_restored_at"] = datetime.now().isoformat()
    manifest_data["fully_restored"] = all(it.get("restored", False) for it in items_data)

    with open(manifest_p, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2, ensure_ascii=False)

    return RestoreResult(
        manifest_path=manifest_p,
        total_restored=total_restored,
        total_bytes_restored=total_bytes_restored,
        skipped_count=skipped_count,
        errors=errors
    )
