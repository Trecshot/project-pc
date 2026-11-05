"""
Subsistema de Persistencia Transaccional en SQLite e Historial de Memoria Recuperada
DataCleaner CLI/GUI

Reemplaza el motor de persistencia plano JSON por el módulo estándar sqlite3
(`.datacleaner.sqlite`), manteniendo intacta la interfaz de `CleaningHistoryManager`
para conservar el acoplamiento con `gui.py` y `cli.py`.
"""

from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Any
import sqlite3
import json


DEFAULT_DATABASE = Path(__file__).resolve().parent.parent / ".datacleaner.sqlite"
DEFAULT_HISTORY_FILE = DEFAULT_DATABASE
LEGACY_JSON_HISTORY = Path(__file__).resolve().parent.parent / ".datacleaner_history.json"


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
    action_type: str        # "QUARANTINE", "HARDLINK", "TRASH", "PERMANENT", "PURGE", "RESTORE"
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
    "HARDLINK": "🔗 Deduplicado con Hardlink (OS)",
    "TRASH": "🗑️ Papelera de Windows",
    "PERMANENT": "⚠️ Eliminación Permanente",
    "PURGE": "💥 Cuarentena Purgada",
    "RESTORE": "🔄 Restaurado a Origen",
}


class CleaningHistoryManager:
    """
    Gestor Transaccional SQLite (`.datacleaner.sqlite`) para el historial de operaciones
    (`operations_history`), sesiones de cuarentena y métricas agregadas en C.
    """

    def __init__(self, history_file: Path | str | None = None, storage_path: Path | str | None = None):
        chosen = history_file or storage_path
        if chosen:
            chosen_path = Path(chosen).resolve()
            if chosen_path.suffix.lower() == ".json":
                self.db_path = chosen_path.with_suffix(".sqlite")
                self.legacy_json_path = chosen_path
            else:
                self.db_path = chosen_path
                self.legacy_json_path = None
        else:
            self.db_path = DEFAULT_DATABASE
            self.legacy_json_path = LEGACY_JSON_HISTORY

        self._init_database()
        self._migrate_legacy_json_if_needed()

    def _get_connection(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_database(self) -> None:
        """Ejecuta la creación condicional del esquema relacional en SQLite."""
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS operations_history (
                    entry_id TEXT PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    action_type TEXT NOT NULL,
                    action_label TEXT NOT NULL,
                    target_dir TEXT NOT NULL,
                    files_count INTEGER NOT NULL,
                    bytes_count INTEGER NOT NULL,
                    details TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_operations_timestamp
                    ON operations_history(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_operations_action
                    ON operations_history(action_type);

                CREATE TABLE IF NOT EXISTS sesiones_cuarentena (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    base_dir TEXT NOT NULL,
                    keep_rule TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    files_count INTEGER NOT NULL DEFAULT 0,
                    bytes_isolated INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS archivos_evaluados (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER NOT NULL DEFAULT 0,
                    fast_hash TEXT DEFAULT '',
                    sha256_hash TEXT DEFAULT '',
                    detected_mime TEXT DEFAULT 'application/octet-stream',
                    integrity_status TEXT DEFAULT 'VERIFIED',
                    action_taken TEXT NOT NULL DEFAULT 'KEEP',
                    FOREIGN KEY(session_id) REFERENCES sesiones_cuarentena(session_id) ON DELETE CASCADE
                );
                """
            )
            conn.commit()

    def _migrate_legacy_json_if_needed(self) -> None:
        """Migra entradas previas de `.datacleaner_history.json` si existiera."""
        if not self.legacy_json_path or not self.legacy_json_path.exists():
            return
        try:
            with self._get_connection() as conn:
                row = conn.execute("SELECT COUNT(*) AS cnt FROM operations_history").fetchone()
                if row and row["cnt"] > 0:
                    return

                with open(self.legacy_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                raw_entries = data.get("entries", [])
                for item in reversed(raw_entries):
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO operations_history
                        (entry_id, timestamp, action_type, action_label, target_dir, files_count, bytes_count, details)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(item.get("entry_id", "")),
                            str(item.get("timestamp", "")),
                            str(item.get("action_type", "QUARANTINE")),
                            str(item.get("action_label", "Operación")),
                            str(item.get("target_dir", "")),
                            int(item.get("files_count", 0)),
                            int(item.get("bytes_count", 0)),
                            str(item.get("details", "")),
                        )
                    )
                conn.commit()
        except Exception:
            pass

    def record_audit_session(
        self,
        session_id: str,
        base_dir: Path | str,
        keep_rule: str,
        status: str,
        files_count: int,
        bytes_isolated: int,
        evaluated_files: list[dict[str, Any]] | None = None
    ) -> None:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO sesiones_cuarentena
                (session_id, timestamp, base_dir, keep_rule, status, files_count, bytes_isolated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    now_str,
                    str(Path(base_dir).resolve()),
                    keep_rule,
                    status,
                    max(0, int(files_count)),
                    max(0, int(bytes_isolated)),
                )
            )
            if evaluated_files:
                conn.executemany(
                    """
                    INSERT INTO archivos_evaluados
                    (session_id, file_path, file_size, fast_hash, sha256_hash, detected_mime, integrity_status, action_taken)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            session_id,
                            str(f.get("file_path", "")),
                            int(f.get("file_size", 0)),
                            str(f.get("fast_hash", "")),
                            str(f.get("sha256_hash", "")),
                            str(f.get("detected_mime", "application/octet-stream")),
                            str(f.get("integrity_status", "VERIFIED")),
                            str(f.get("action_taken", "KEEP")),
                        )
                        for f in evaluated_files
                    ]
                )
            conn.commit()

    def update_quarantine_session_status(self, session_id: str, new_status: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE sesiones_cuarentena SET status = ? WHERE session_id = ?",
                (new_status, session_id)
            )
            conn.commit()

    def get_entries(self) -> list[HistoryEntry]:
        return self.load_entries()

    def load_entries(self) -> list[HistoryEntry]:
        """Consulta directa sobre `operations_history` ordenada por timestamp DESC."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM operations_history ORDER BY timestamp DESC, rowid DESC"
            ).fetchall()

        return [
            HistoryEntry(
                entry_id=r["entry_id"],
                timestamp=r["timestamp"],
                action_type=r["action_type"],
                action_label=r["action_label"],
                target_dir=r["target_dir"],
                files_count=r["files_count"],
                bytes_count=r["bytes_count"],
                details=r["details"] or "",
            )
            for r in rows
        ]

    def record_event(
        self,
        action_type: str,
        target_dir: Path | str,
        files_count: int,
        bytes_count: int | None = None,
        details: str = "",
        bytes_affected: int | None = None,
    ) -> HistoryEntry:
        """Inserta un nuevo evento en `operations_history` mediante sentencia SQL parametrizada."""
        now = datetime.now()
        actual_bytes = bytes_count if bytes_count is not None else (bytes_affected or 0)
        label = ACTION_LABELS.get(action_type, action_type)

        with self._get_connection() as conn:
            row = conn.execute("SELECT COALESCE(MAX(rowid), 0) + 1 AS next_id FROM operations_history").fetchone()
            next_id = row["next_id"] if row else 1
            entry_id = f"hist_{now.strftime('%Y%m%d_%H%M%S_%f')}_{next_id}"

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

            conn.execute(
                """
                INSERT INTO operations_history
                (entry_id, timestamp, action_type, action_label, target_dir, files_count, bytes_count, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_entry.entry_id,
                    new_entry.timestamp,
                    new_entry.action_type,
                    new_entry.action_label,
                    new_entry.target_dir,
                    new_entry.files_count,
                    new_entry.bytes_count,
                    new_entry.details,
                )
            )
            conn.commit()

        return new_entry

    def get_summary(self) -> HistorySummary:
        """
        Optimización Crítica: Delega el cálculo de métricas al motor SQL (SUM, COUNT)
        sobre `operations_history` sin iterar objetos en memoria Python.
        """
        with self._get_connection() as conn:
            agg = conn.execute(
                """
                SELECT 
                    COUNT(*) as total_ops,
                    COALESCE(SUM(CASE WHEN action_type IN ('QUARANTINE', 'HARDLINK', 'TRASH', 'PERMANENT') THEN files_count ELSE 0 END), 0) -
                    COALESCE(SUM(CASE WHEN action_type = 'RESTORE' THEN files_count ELSE 0 END), 0) as net_files,
                    COALESCE(SUM(CASE WHEN action_type IN ('QUARANTINE', 'HARDLINK', 'TRASH', 'PERMANENT') THEN bytes_count ELSE 0 END), 0) - 
                    COALESCE(SUM(CASE WHEN action_type = 'RESTORE' THEN bytes_count ELSE 0 END), 0) as net_bytes,
                    COALESCE(SUM(CASE WHEN action_type IN ('PERMANENT', 'PURGE') THEN bytes_count ELSE 0 END), 0) as purged_bytes
                FROM operations_history;
                """
            ).fetchone()

        total_ops = max(0, int(agg["total_ops"] or 0)) if agg else 0
        net_files = max(0, int(agg["net_files"] or 0)) if agg else 0
        net_bytes = max(0, int(agg["net_bytes"] or 0)) if agg else 0
        purged_forever_bytes = max(0, int(agg["purged_bytes"] or 0)) if agg else 0

        entries = self.load_entries()

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
        with self._get_connection() as conn:
            conn.executescript(
                """
                DELETE FROM operations_history;
                DELETE FROM archivos_evaluados;
                DELETE FROM sesiones_cuarentena;
                """
            )
            conn.commit()
        if self.legacy_json_path and self.legacy_json_path.exists():
            self.legacy_json_path.unlink(missing_ok=True)

    def export_history_json(self, output_path: Path | str) -> Path:
        summary = self.get_summary()
        out = Path(output_path).resolve()
        data = {
            "exported_at": datetime.now().isoformat(),
            "storage_engine": "SQLite3 (operations_history)",
            "database_path": str(self.db_path),
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
