"""
Subsistema de Historial de Limpieza y Estadísticas Acumuladas de Memoria Recuperada
DataCleaner CLI/GUI

Registra de forma persistente todas las operaciones de limpieza de redundancias
(Cuarentena, Papelera de Reciclaje, Eliminación Permanente, Purgado y Restauración)
y calcula el ahorro acumulado con conversión automática de unidades (B, KB, MB, GB, TB).
"""

from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Any
import json


DEFAULT_HISTORY_FILE = Path(__file__).resolve().parent.parent / ".datacleaner_history.json"


def format_bytes_auto(bytes_count: int | float, target_unit: str = "AUTO") -> str:
    """
    Convierte una cantidad de bytes a una representación legible con escalado automático
    (B -> KB -> MB -> GB -> TB -> PB) o hacia una unidad específica ('KB', 'MB', 'GB', 'TB').
    """
    if bytes_count <= 0:
        if target_unit in ("KB", "MB", "GB", "TB"):
            return f"0.00 {target_unit}"
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    target_upper = target_unit.upper().strip()

    if target_upper in units and target_upper != "B":
        idx = units.index(target_upper)
        val = bytes_count / (1024.0 ** idx)
        if val >= 100:
            return f"{val:,.2f} {target_upper}"
        elif val >= 1:
            return f"{val:.2f} {target_upper}"
        else:
            return f"{val:.4f} {target_upper}"

    # Modo AUTO: escala automáticamente a la siguiente unidad (KB -> MB -> GB -> TB) al llegar a 1000
    val = float(bytes_count)
    unit_idx = 0
    while val >= 1000.0 and unit_idx < len(units) - 1:
        val /= 1024.0
        unit_idx += 1

    if unit_idx == 0:
        return f"{int(val):,} B"
    return f"{val:,.2f} {units[unit_idx]}"


def format_bytes_with_equivalence(bytes_count: int) -> str:
    """
    Devuelve la unidad principal auto-escalada junto con su equivalencia inmediata
    (por ejemplo: '1.45 GB (1,484.80 MB)' o '450.00 MB (0.44 GB)').
    """
    if bytes_count <= 0:
        return "0 B (0.00 MB / 0.00 GB)"

    gb_val = bytes_count / (1024.0 ** 3)
    mb_val = bytes_count / (1024.0 ** 2)
    kb_val = bytes_count / 1024.0

    if bytes_count >= 1024 ** 3:
        return f"{gb_val:,.2f} GB  ({mb_val:,.2f} MB)"
    elif bytes_count >= 1024 ** 2:
        return f"{mb_val:,.2f} MB  ({gb_val:.3f} GB · {kb_val:,.0f} KB)"
    elif bytes_count >= 1024:
        return f"{kb_val:,.2f} KB  ({mb_val:.3f} MB)"
    else:
        return f"{bytes_count:,} B  ({kb_val:.2f} KB)"


@dataclass
class HistoryEntry:
    entry_id: str
    timestamp: str
    action_type: str        # "QUARANTINE", "TRASH", "PERMANENT", "PURGE", "RESTORE"
    action_label: str       # Etiqueta legible para la UI
    target_dir: str
    files_count: int
    bytes_count: int
    details: str = ""

    @property
    def bytes_affected(self) -> int:
        return self.bytes_count

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HistorySummary:
    total_operations: int
    total_files_cleaned: int
    total_bytes_recovered: int
    total_bytes_purged_forever: int
    recovered_auto: str
    recovered_equivalence: str
    recovered_in_gb: str
    recovered_in_mb: str
    entries: list[HistoryEntry]

    @property
    def total_bytes_purged(self) -> int:
        return self.total_bytes_purged_forever


ACTION_LABELS = {
    "QUARANTINE": "📦 Aislado en Cuarentena",
    "TRASH": "🗑️ Papelera de Windows",
    "PERMANENT": "⚠️ Eliminación Permanente",
    "PURGE": "💥 Cuarentena Purgada",
    "RESTORE": "🔄 Restaurado a Origen",
}


class CleaningHistoryManager:
    """Gestor de persistencia y consulta del historial de limpiezas y memoria recuperada."""

    def __init__(self, history_file: Path | str | None = None, storage_path: Path | str | None = None):
        chosen = history_file or storage_path
        self.history_file = Path(chosen).resolve() if chosen else DEFAULT_HISTORY_FILE

    def get_entries(self) -> list[HistoryEntry]:
        return self.load_entries()

    def load_entries(self) -> list[HistoryEntry]:
        if not self.history_file.exists():
            return []
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            raw_list = data.get("entries", [])
            entries = []
            for item in raw_list:
                entries.append(
                    HistoryEntry(
                        entry_id=str(item.get("entry_id", "")),
                        timestamp=str(item.get("timestamp", "")),
                        action_type=str(item.get("action_type", "QUARANTINE")),
                        action_label=str(item.get("action_label", "Operación")),
                        target_dir=str(item.get("target_dir", "")),
                        files_count=int(item.get("files_count", 0)),
                        bytes_count=int(item.get("bytes_count", 0)),
                        details=str(item.get("details", "")),
                    )
                )
            return entries
        except Exception:
            return []

    def save_entries(self, entries: list[HistoryEntry]) -> None:
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_entries": len(entries),
            "entries": [asdict(e) for e in entries]
        }
        with open(self.history_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

    def record_event(
        self,
        action_type: str,
        target_dir: Path | str,
        files_count: int,
        bytes_count: int | None = None,
        details: str = "",
        bytes_affected: int | None = None,
    ) -> HistoryEntry:
        """Registra un nuevo evento de limpieza o restauración en el historial persistente."""
        now = datetime.now()
        entries = self.load_entries()
        entry_id = f"hist_{now.strftime('%Y%m%d_%H%M%S')}_{len(entries) + 1}"
        label = ACTION_LABELS.get(action_type, action_type)
        actual_bytes = bytes_count if bytes_count is not None else (bytes_affected or 0)

        new_entry = HistoryEntry(
            entry_id=entry_id,
            timestamp=now.strftime("%Y-%m-%d %H:%M:%S"),
            action_type=action_type,
            action_label=label,
            target_dir=str(Path(target_dir).resolve()),
            files_count=max(0, int(files_count)),
            bytes_count=max(0, int(actual_bytes)),
            details=details,
        )
        # Insertar al principio (más reciente primero)
        entries.insert(0, new_entry)
        self.save_entries(entries)
        return new_entry

    def get_summary(self) -> HistorySummary:
        """
        Calcula los totales acumulados de archivos redundantes limpiados y memoria recuperada.
        - Las acciones QUARANTINE, TRASH y PERMANENT suman al espacio recuperado del directorio activo.
        - Si una sesión se RESTAURA (RESTORE), se descuentan esos bytes porque volvieron a su origen.
        - Si una cuarentena se PURGA (PURGE), se registra la liberación definitiva sin duplicar el conteo.
        """
        entries = self.load_entries()
        total_ops = 0
        net_files = 0
        net_bytes = 0
        purged_forever_bytes = 0

        # Procesar en orden cronológico (del más antiguo al más reciente) para evitar negativos
        for e in reversed(entries):
            if e.action_type in ("QUARANTINE", "TRASH", "PERMANENT"):
                total_ops += 1
                net_files += e.files_count
                net_bytes += e.bytes_count
                if e.action_type == "PERMANENT":
                    purged_forever_bytes += e.bytes_count
            elif e.action_type == "PURGE":
                total_ops += 1
                purged_forever_bytes += e.bytes_count
            elif e.action_type == "RESTORE":
                net_files = max(0, net_files - e.files_count)
                net_bytes = max(0, net_bytes - e.bytes_count)

        return HistorySummary(
            total_operations=total_ops,
            total_files_cleaned=net_files,
            total_bytes_recovered=net_bytes,
            total_bytes_purged_forever=purged_forever_bytes,
            recovered_auto=format_bytes_auto(net_bytes, "AUTO"),
            recovered_equivalence=format_bytes_with_equivalence(net_bytes),
            recovered_in_gb=format_bytes_auto(net_bytes, "GB"),
            recovered_in_mb=format_bytes_auto(net_bytes, "MB"),
            entries=entries
        )

    def clear_history(self) -> None:
        if self.history_file.exists():
            self.history_file.unlink(missing_ok=True)

    def export_history_json(self, output_path: Path | str) -> Path:
        summary = self.get_summary()
        out = Path(output_path).resolve()
        data = {
            "exported_at": datetime.now().isoformat(),
            "total_operations": summary.total_operations,
            "total_files_cleaned": summary.total_files_cleaned,
            "total_bytes_recovered": summary.total_bytes_recovered,
            "recovered_formatted": summary.recovered_auto,
            "recovered_in_gb": summary.recovered_in_gb,
            "recovered_in_mb": summary.recovered_in_mb,
            "entries": [asdict(e) for e in summary.entries]
        }
        with open(out, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return out
