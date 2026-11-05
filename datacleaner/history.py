"""
Subsistema de Persistencia Transaccional en SQLite e Historial de Memoria Recuperada
DataCleaner CLI/GUI

Migra el almacenamiento de auditoría e historial desde JSON plano hacia una base de datos
relacional local en SQLite con modo WAL (Write-Ahead Logging) para concurrencia segura
y consultas agregadas en tiempo O(log N) sin cargar todo el historial en memoria RAM (RNF-01).

Esquema relacional normalizado:
1. Tabla `sesiones_cuarentena`: Registro de sesiones de auditoría, aislamiento y su estado.
2. Tabla `archivos_evaluados`: Detalle forense por archivo (SHA-256, Fast-Hash, MIME real, integridad).
3. Tabla `metricas_recuperacion`: Eventos de recuperación de espacio (Cuarentena, Hardlink, Papelera, Purga, Restauración).
"""

from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Any
import sqlite3
import json


DEFAULT_SQLITE_DB = Path(__file__).resolve().parent.parent / ".datacleaner_audit.db"
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
    Gestor Transaccional SQLite para auditoría forense, sesiones de cuarentena,
    archivos evaluados y métricas de recuperación de memoria en O(log N).
    """

    def __init__(self, history_file: Path | str | None = None, storage_path: Path | str | None = None):
        chosen = history_file or storage_path
        if chosen:
            chosen_path = Path(chosen).resolve()
            # Si un test o llamador pasa una ruta .json, usamos un archivo .db SQLite asociado
            if chosen_path.suffix.lower() == ".json":
                self.db_path = chosen_path.with_suffix(".db")
                self.legacy_json_path = chosen_path
            else:
                self.db_path = chosen_path
                self.legacy_json_path = None
        else:
            self.db_path = DEFAULT_SQLITE_DB
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
        """Crea las 3 tablas normalizadas (`sesiones_cuarentena`, `archivos_evaluados`, `metricas_recuperacion`) e índices B-Tree."""
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.executescript(
                """
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

                CREATE INDEX IF NOT EXISTS idx_sesiones_timestamp
                    ON sesiones_cuarentena(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_sesiones_base_dir
                    ON sesiones_cuarentena(base_dir);

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

                CREATE INDEX IF NOT EXISTS idx_archivos_session
                    ON archivos_evaluados(session_id);
                CREATE INDEX IF NOT EXISTS idx_archivos_sha256
                    ON archivos_evaluados(sha256_hash);
                CREATE INDEX IF NOT EXISTS idx_archivos_integrity
                    ON archivos_evaluados(integrity_status);

                CREATE TABLE IF NOT EXISTS metricas_recuperacion (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    action_label TEXT NOT NULL,
                    target_dir TEXT NOT NULL,
                    files_count INTEGER NOT NULL DEFAULT 0,
                    bytes_count INTEGER NOT NULL DEFAULT 0,
                    details TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_metricas_timestamp
                    ON metricas_recuperacion(timestamp DESC, id DESC);
                CREATE INDEX IF NOT EXISTS idx_metricas_action
                    ON metricas_recuperacion(action_type);
                """
            )
            conn.commit()

    def _migrate_legacy_json_if_needed(self) -> None:
        """Migra automáticamente el archivo histórico JSON previo a la tabla SQLite si existiera."""
        if not self.legacy_json_path or not self.legacy_json_path.exists():
            return
        try:
            with self._get_connection() as conn:
                row = conn.execute("SELECT COUNT(*) AS cnt FROM metricas_recuperacion").fetchone()
                if row and row["cnt"] > 0:
                    return

                with open(self.legacy_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                raw_entries = data.get("entries", [])
                # Insertar desde el más antiguo al más reciente para preservar el orden de IDs
                for item in reversed(raw_entries):
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO metricas_recuperacion
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
        """
        Registra transaccionalmente una sesión en `sesiones_cuarentena` y sus archivos
        auditados en `archivos_evaluados`.
        """
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
        """Actualiza el estado de una sesión en `sesiones_cuarentena` (ej. RESTORED, PURGED)."""
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE sesiones_cuarentena SET status = ? WHERE session_id = ?",
                (new_status, session_id)
            )
            conn.commit()

    def get_entries(self, limit: int = 500) -> list[HistoryEntry]:
        return self.load_entries(limit=limit)

    def load_entries(self, limit: int = 500) -> list[HistoryEntry]:
        """Consulta paginada en O(log N) desde `metricas_recuperacion` sin saturar RAM."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT entry_id, timestamp, action_type, action_label,
                       target_dir, files_count, bytes_count, details
                FROM metricas_recuperacion
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,)
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
                details=r["details"],
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
        """Inserta transaccionalmente una métrica de recuperación en SQLite (`metricas_recuperacion`)."""
        now = datetime.now()
        actual_bytes = bytes_count if bytes_count is not None else (bytes_affected or 0)
        label = ACTION_LABELS.get(action_type, action_type)

        with self._get_connection() as conn:
            row = conn.execute("SELECT COALESCE(MAX(id), 0) + 1 AS next_id FROM metricas_recuperacion").fetchone()
            next_id = row["next_id"] if row else 1
            entry_id = f"hist_{now.strftime('%Y%m%d_%H%M%S')}_{next_id}"

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
                INSERT INTO metricas_recuperacion
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

    def get_summary(self, limit_entries: int = 500) -> HistorySummary:
        """
        Calcula mediante agregación SQL en SQLite (sin cargar millones de registros en RAM):
        - `QUARANTINE`, `HARDLINK`, `TRASH` y `PERMANENT` suman al espacio recuperado.
        - `RESTORE` descuenta los archivos/bytes devueltos a su ubicación original.
        - `PURGE` y `PERMANENT` suman al volumen destruido/purgado definitivamente.
        """
        with self._get_connection() as conn:
            agg = conn.execute(
                """
                SELECT
                    COALESCE(SUM(CASE WHEN action_type IN ('QUARANTINE', 'HARDLINK', 'TRASH', 'PERMANENT', 'PURGE') THEN 1 ELSE 0 END), 0) AS total_ops,
                    COALESCE(SUM(CASE
                        WHEN action_type IN ('QUARANTINE', 'HARDLINK', 'TRASH', 'PERMANENT') THEN files_count
                        WHEN action_type = 'RESTORE' THEN -files_count
                        ELSE 0
                    END), 0) AS net_files,
                    COALESCE(SUM(CASE
                        WHEN action_type IN ('QUARANTINE', 'HARDLINK', 'TRASH', 'PERMANENT') THEN bytes_count
                        WHEN action_type = 'RESTORE' THEN -bytes_count
                        ELSE 0
                    END), 0) AS net_bytes,
                    COALESCE(SUM(CASE
                        WHEN action_type IN ('PERMANENT', 'PURGE') THEN bytes_count
                        ELSE 0
                    END), 0) AS purged_forever_bytes
                FROM metricas_recuperacion
                """
            ).fetchone()

        total_ops = max(0, int(agg["total_ops"])) if agg else 0
        net_files = max(0, int(agg["net_files"])) if agg else 0
        net_bytes = max(0, int(agg["net_bytes"])) if agg else 0
        purged_forever_bytes = max(0, int(agg["purged_forever_bytes"])) if agg else 0

        entries = self.load_entries(limit=limit_entries)

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
        """Limpia transaccionalmente las tablas de historial en SQLite."""
        with self._get_connection() as conn:
            conn.executescript(
                """
                DELETE FROM archivos_evaluados;
                DELETE FROM sesiones_cuarentena;
                DELETE FROM metricas_recuperacion;
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
            "storage_engine": "SQLite3 (WAL Transactional)",
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
