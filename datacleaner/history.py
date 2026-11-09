"""
Subsistema de Persistencia Transaccional en SQLite e Historial de Memoria Recuperada
DataCleaner CLI/GUI

Reemplaza el motor de persistencia plano JSON por el módulo estándar sqlite3
(`.datacleaner.sqlite`), manteniendo intacta la interfaz de `CleaningHistoryManager`
para conservar el acoplamiento con `gui.py` y `cli.py`.
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Any
import sqlite3
import json
import logging
import hashlib
import hmac
import subprocess

logger = logging.getLogger(__name__)


def _get_default_storage_dir() -> Path:
    env_db = os.environ.get("DATACLEANER_DB_PATH")
    if env_db:
        return Path(env_db).resolve().parent
    # Si se ejecuta compilado con Nuitka / PyInstaller, usar AppData Local del usuario
    if "__compiled__" in globals() or getattr(sys, "frozen", False):
        base = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "DataCleaner"
        base.mkdir(parents=True, exist_ok=True)
        return base
    return Path(__file__).resolve().parent.parent


def _get_default_db_path() -> Path:
    env_db = os.environ.get("DATACLEANER_DB_PATH")
    if env_db:
        return Path(env_db).resolve()
    return _get_default_storage_dir() / ".datacleaner.sqlite"


DEFAULT_DATABASE = _get_default_db_path()
DEFAULT_HISTORY_FILE = DEFAULT_DATABASE
LEGACY_JSON_HISTORY = _get_default_storage_dir() / ".datacleaner_history.json"


def get_utc_timestamp() -> str:
    """Devuelve timestamp estandarizado en UTC para todas las tablas (Falla 5)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _get_audit_secret_key() -> bytes:
    """Obtiene la clave de auditoría del entorno o almacén seguro del SO (Falla 3 / Auditoría C)."""
    from datacleaner.security import get_audit_secret_key
    return get_audit_secret_key()


def compute_entry_hmac(prev_hash: str, entry_id: str, timestamp: str, action_type: str, target_dir: str, files_count: int, bytes_count: int) -> str:
    """Calcula un HMAC-SHA256 inmutable para el registro de auditoría (NIST SSDF PO.4 / Falla 3)."""
    payload = f"{prev_hash}|{entry_id}|{timestamp}|{action_type}|{target_dir}|{files_count}|{bytes_count}".encode("utf-8")
    return hmac.new(_get_audit_secret_key(), payload, hashlib.sha256).hexdigest()


def reseal_legacy_audit_chain(conn: sqlite3.Connection) -> None:
    """Repara cadenas rotas (como las filas 1 a 11) sellando desde el primer registro con HMAC."""
    cursor = conn.execute(
        "SELECT entry_id, timestamp, action_type, target_dir, files_count, bytes_count FROM operations_history ORDER BY rowid ASC"
    )
    rows = cursor.fetchall()
    prev_hash = "GENESIS"
    for row in rows:
        entry_hash = compute_entry_hmac(
            prev_hash, row["entry_id"], row["timestamp"], row["action_type"],
            row["target_dir"], row["files_count"], row["bytes_count"]
        )
        conn.execute(
            "UPDATE operations_history SET prev_hash = ?, entry_hash = ? WHERE entry_id = ?",
            (prev_hash, entry_hash, row["entry_id"])
        )
        prev_hash = entry_hash
    conn.commit()


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
    prev_hash: str = "GENESIS"
    entry_hash: str = ""

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


class ManagedConnection(sqlite3.Connection):
    """Conexión SQLite que asegura el cierre automático al salir del context manager (`with`)."""
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            super().__exit__(exc_type, exc_val, exc_tb)
        finally:
            self.close()


def _harden_file_permissions(file_path: Path) -> None:
    """Restringe permisos del archivo a sólo el usuario creador (Principio de Menor Privilegio, NIST SSDF PO.5.1 / PW.5.1)."""
    if not file_path.exists():
        return
    try:
        if sys.platform != "win32":
            os.chmod(file_path, 0o600)
        else:
            # Eliminar herencia y restringir acceso exclusivamente al usuario propietario actual (Windows DACL)
            username = os.environ.get("USERNAME")
            if username:
                # Restringir acceso exclusivamente al usuario propietario actual (Windows DACL)
                cmd = ["icacls", str(file_path), "/inheritance:r", "/grant:r", f"{username}:(F)"]
                subprocess.run(cmd, shell=False, capture_output=True, check=False)
    except (OSError, Exception) as e:
        logger.debug(f"No se pudieron ajustar permisos para {file_path}: {e}")


class CleaningHistoryManager:
    """
    Gestor Transaccional SQLite (`.datacleaner.sqlite`) para el historial de operaciones
    (`operations_history`), sesiones de cuarentena y métricas agregadas en C.
    """

    def __init__(self, history_file: Path | str | None = None, storage_path: Path | str | None = None):
        env_db = os.environ.get("DATACLEANER_DB_PATH")
        chosen = history_file or storage_path or env_db
        if chosen:
            chosen_path = Path(chosen).resolve()
            if chosen_path.suffix.lower() == ".json":
                self.db_path = chosen_path.with_suffix(".sqlite")
                self.legacy_json_path = chosen_path
            else:
                self.db_path = chosen_path
                self.legacy_json_path = None
        else:
            self.db_path = _get_default_db_path()
            self.legacy_json_path = LEGACY_JSON_HISTORY

        self._init_database()
        self._migrate_legacy_json_if_needed()

    def _get_connection(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, factory=ManagedConnection)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA secure_delete = ON;")  # Sobrescribe con 0x00 páginas borradas (Falla 4)

        # Endurecer permisos del archivo de base de datos
        _harden_file_permissions(self.db_path)
        return conn

    def _init_database(self) -> None:
        """Ejecuta la creación condicional del esquema relacional en SQLite."""
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode = WAL;")

            # Si la tabla de caché fue creada previamente con columnas INTEGER, recrearla con TEXT
            cursor = conn.execute("PRAGMA table_info(file_hash_cache)")
            cols = {row["name"]: str(row["type"]).upper() for row in cursor.fetchall()}
            if cols.get("device_id") == "INTEGER" or cols.get("inode") == "INTEGER":
                conn.execute("DROP TABLE IF EXISTS file_hash_cache;")

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
                    details TEXT,
                    prev_hash TEXT DEFAULT 'GENESIS',
                    entry_hash TEXT DEFAULT ''
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

                CREATE TABLE IF NOT EXISTS file_hash_cache (
                    file_path TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL DEFAULT '',
                    inode TEXT NOT NULL DEFAULT '',
                    file_size INTEGER NOT NULL,
                    mtime REAL NOT NULL,
                    partial_hash TEXT,
                    sha256_hash TEXT NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_cache_inode_mtime
                    ON file_hash_cache(device_id, inode, mtime);
                CREATE INDEX IF NOT EXISTS idx_cache_path_mtime
                    ON file_hash_cache(file_path, mtime);
                """
            )

            # Migración: agregar columnas de encadenamiento criptográfico si la BD fue creada previamente
            cur_ops = conn.execute("PRAGMA table_info(operations_history)")
            ops_cols = {row["name"] for row in cur_ops.fetchall()}
            if "prev_hash" not in ops_cols:
                conn.execute("ALTER TABLE operations_history ADD COLUMN prev_hash TEXT DEFAULT 'GENESIS';")
            if "entry_hash" not in ops_cols:
                conn.execute("ALTER TABLE operations_history ADD COLUMN entry_hash TEXT DEFAULT '';")

            # Resellar cadenas legacy o corruptas con HMAC (Falla 3)
            cur_check = conn.execute(
                "SELECT entry_id, timestamp, action_type, target_dir, files_count, bytes_count, prev_hash, entry_hash "
                "FROM operations_history ORDER BY rowid ASC LIMIT 1"
            ).fetchone()
            if cur_check:
                expected_first = compute_entry_hmac(
                    "GENESIS", cur_check["entry_id"], cur_check["timestamp"],
                    cur_check["action_type"], cur_check["target_dir"],
                    cur_check["files_count"], cur_check["bytes_count"]
                )
                if cur_check["entry_hash"] != expected_first or not cur_check["entry_hash"]:
                    reseal_legacy_audit_chain(conn)

            conn.commit()
        # Mantenimiento preventivo: podar registros obsoletos (> 60 días)
        try:
            self.cleanup_obsolete_cache(days=60)
        except Exception as e:
            logger.debug(f"Aviso durante poda de caché en inicio: {e}")

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

    def cleanup_obsolete_cache(self, days: int = 60) -> int:
        """
        Poda registros de caché y sesiones temporales antiguas para prevenir
        el crecimiento indefinido de la base de datos (MED-03).
        """
        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "DELETE FROM file_hash_cache WHERE updated_at < datetime('now', ?)",
                    (f"-{days} days",)
                )
                purged_cache = cur.rowcount
                conn.execute(
                    "DELETE FROM sesiones_cuarentena WHERE status = 'DRY_RUN_COMPLETED' AND timestamp < datetime('now', '-30 days')"
                )
                conn.commit()
                return purged_cache
        except Exception as e:
            logger.warning(f"Error en limpieza de registros obsoletos de base de datos: {e}")
            return 0

    def invalidate_cache_entries(self, file_paths: list[Path | str]) -> int:
        """
        Invalida/elimina de file_hash_cache las rutas que hayan sido borradas o movidas (MED-03).
        """
        if not file_paths:
            return 0
        deleted_count = 0
        try:
            with self._get_connection() as conn:
                del_sql = (
                    "DELETE FROM file_hash_cache WHERE file_path = ? COLLATE NOCASE"
                    if sys.platform == "win32"
                    else "DELETE FROM file_hash_cache WHERE file_path = ?"
                )
                for p in file_paths:
                    p_str = str(Path(p).resolve())
                    cur = conn.execute(del_sql, (p_str,))
                    deleted_count += cur.rowcount
                conn.commit()
        except Exception as e:
            logger.warning(f"Error invalidando entradas en file_hash_cache: {e}")
        return deleted_count

    def load_cache_for_directory(self, base_dir: Path | str) -> dict[str, Any]:
        """
        Carga en memoria todos los registros de caché correspondientes al directorio base
        en una sola consulta SQL agrupada, permitiendo búsquedas O(1) en memoria sin
        abrir conexiones SQLite repetidas durante el escaneo.
        Incorpora COLLATE NOCASE en Windows para evitar pérdidas de cache hits por case-sensitivity (CRIT-04).
        """
        resolved_dir = str(Path(base_dir).resolve())
        prefix = resolved_dir if resolved_dir.endswith(os.sep) else resolved_dir + os.sep
        by_path: dict[str, dict[str, Any]] = {}
        by_inode: dict[tuple[str, str], dict[str, Any]] = {}

        try:
            with self._get_connection() as conn:
                select_sql = (
                    """
                    SELECT file_path, device_id, inode, file_size, mtime, partial_hash, sha256_hash
                    FROM file_hash_cache
                    WHERE substr(file_path, 1, ?) = ? COLLATE NOCASE
                    """
                    if sys.platform == "win32"
                    else """
                    SELECT file_path, device_id, inode, file_size, mtime, partial_hash, sha256_hash
                    FROM file_hash_cache
                    WHERE substr(file_path, 1, ?) = ?
                    """
                )
                rows = conn.execute(select_sql, (len(prefix), prefix)).fetchall()

                for r in rows:
                    entry = {
                        "file_path": r["file_path"],
                        "device_id": str(r["device_id"]),
                        "inode": str(r["inode"]),
                        "file_size": int(r["file_size"]),
                        "mtime": float(r["mtime"]),
                        "partial_hash": r["partial_hash"],
                        "sha256_hash": r["sha256_hash"],
                    }
                    orig_p = r["file_path"]
                    by_path[orig_p] = entry
                    norm_p = os.path.normcase(orig_p)
                    by_path[norm_p] = entry
                    dev = str(r["device_id"] or "")
                    ino = str(r["inode"] or "")
                    if ino and ino != "0":
                        by_inode[(dev, ino)] = entry
        except Exception as e:
            logger.warning(f"Error al cargar caché de directorio para '{base_dir}': {e}")

        return {"by_path": by_path, "by_inode": by_inode}

    def get_cached_file_hash(
        self,
        file_path: Path | str,
        device_id: int | str,
        inode: int | str,
        mtime: float,
        file_size: int,
    ) -> tuple[str | None, str | None]:
        """
        Consulta de Estado Diferencial en O(1):
        Si el archivo coincide en (device_id, inode, mtime) o (file_path, mtime, file_size),
        asume matemáticamente que el contenido es idéntico y devuelve (partial_hash, sha256_hash).
        """
        p_str = str(Path(file_path).resolve())
        dev_str = str(device_id)
        ino_str = str(inode)
        with self._get_connection() as conn:
            # 1. Búsqueda preferente por inodo y mtime si el inodo es válido y no vacío
            if ino_str and ino_str != "0":
                row = conn.execute(
                    """
                    SELECT partial_hash, sha256_hash, file_size, mtime
                    FROM file_hash_cache
                    WHERE device_id = ? AND inode = ?
                    LIMIT 1
                    """,
                    (dev_str, ino_str),
                ).fetchone()
                if row and abs(float(row["mtime"]) - float(mtime)) < 1e-4 and int(row["file_size"]) == file_size:
                    return row["partial_hash"], row["sha256_hash"]

            # 2. Búsqueda alternativa por ruta canónica y mtime (con COLLATE NOCASE en Windows)
            query_path_sql = (
                """
                SELECT partial_hash, sha256_hash, file_size, mtime
                FROM file_hash_cache
                WHERE file_path = ? COLLATE NOCASE
                LIMIT 1
                """
                if sys.platform == "win32"
                else """
                SELECT partial_hash, sha256_hash, file_size, mtime
                FROM file_hash_cache
                WHERE file_path = ?
                LIMIT 1
                """
            )
            row = conn.execute(query_path_sql, (p_str,)).fetchone()
            if row and abs(float(row["mtime"]) - float(mtime)) < 1e-4 and int(row["file_size"]) == file_size:
                return row["partial_hash"], row["sha256_hash"]

        return None, None

    def set_cached_file_hash(
        self,
        file_path: Path | str,
        device_id: int | str,
        inode: int | str,
        mtime: float,
        file_size: int,
        partial_hash: str | None,
        sha256_hash: str,
    ) -> None:
        """Guarda o actualiza el estado de hash de un archivo en la caché de SQLite con timestamp UTC."""
        p_str = str(Path(file_path).resolve())
        utc_now = get_utc_timestamp()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO file_hash_cache
                (file_path, device_id, inode, file_size, mtime, partial_hash, sha256_hash, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    p_str,
                    str(device_id),
                    str(inode),
                    file_size,
                    float(mtime),
                    partial_hash,
                    sha256_hash,
                    utc_now,
                ),
            )
            conn.commit()

    def get_cached_hash(self, file_path: str, file_size: int, mtime: float, current_partial_hash: str) -> str | None:
        """Verifica tamaño, mtime y partial_hash antes de confiar en el SHA-256 de la caché (Falla 6)."""
        p_str = str(Path(file_path).resolve())
        query = (
            """
            SELECT sha256_hash FROM file_hash_cache
            WHERE (file_path = ? OR file_path = ? COLLATE NOCASE)
              AND file_size = ? AND mtime = ? AND partial_hash = ?
            LIMIT 1
            """
            if sys.platform == "win32"
            else """
            SELECT sha256_hash FROM file_hash_cache
            WHERE file_path = ? AND file_size = ? AND mtime = ? AND partial_hash = ?
            LIMIT 1
            """
        )
        with self._get_connection() as conn:
            params = (p_str, file_path, file_size, mtime, current_partial_hash) if sys.platform == "win32" else (file_path, file_size, mtime, current_partial_hash)
            row = conn.execute(query, params).fetchone()
            if row:
                return row["sha256_hash"]
            # Tolerancia para precisión de punto flotante en SQLite
            query_tol = (
                """
                SELECT sha256_hash, mtime FROM file_hash_cache
                WHERE (file_path = ? OR file_path = ? COLLATE NOCASE)
                  AND file_size = ? AND partial_hash = ?
                LIMIT 1
                """
                if sys.platform == "win32"
                else """
                SELECT sha256_hash, mtime FROM file_hash_cache
                WHERE file_path = ? AND file_size = ? AND partial_hash = ?
                LIMIT 1
                """
            )
            params_tol = (p_str, file_path, file_size, current_partial_hash) if sys.platform == "win32" else (file_path, file_size, current_partial_hash)
            row_tol = conn.execute(query_tol, params_tol).fetchone()
            if row_tol and abs(float(row_tol["mtime"]) - float(mtime)) < 1e-4:
                return row_tol["sha256_hash"]
            return None

    def purge_test_artifacts_and_vacuum(self) -> None:
        """Elimina toda la contaminación de tests en la BD y limpia el espacio libre (Falla 4)."""
        with self._get_connection() as conn:
            conn.execute(
                "DELETE FROM file_hash_cache WHERE file_path LIKE '%Temp%datacleaner_%' "
                "OR file_path LIKE '%Temp%tmp%' "
                "OR file_path LIKE '%Temp%dc_test_%' "
                "OR file_path LIKE '%pytest%';"
            )
            conn.execute(
                "DELETE FROM operations_history WHERE target_dir LIKE '%Temp%datacleaner_%' "
                "OR target_dir LIKE '%pytest%';"
            )
            conn.execute(
                "DELETE FROM sesiones_cuarentena WHERE base_dir LIKE '%Temp%datacleaner_%' "
                "OR base_dir LIKE '%pytest%';"
            )
            reseal_legacy_audit_chain(conn)
            conn.commit()
            conn.isolation_level = None
            conn.execute("VACUUM;")

    def set_cached_hashes_batch(self, records: list[dict[str, Any]]) -> None:
        """Inserción por lote para minimizar transacciones en escaneos masivos con timestamp UTC."""
        if not records:
            return
        utc_now = get_utc_timestamp()
        with self._get_connection() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO file_hash_cache
                (file_path, device_id, inode, file_size, mtime, partial_hash, sha256_hash, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        str(r["file_path"]),
                        str(r.get("device_id", "")),
                        str(r.get("inode", "")),
                        int(r["file_size"]),
                        float(r["mtime"]),
                        r.get("partial_hash"),
                        str(r["sha256_hash"]),
                        utc_now,
                    )
                    for r in records
                ],
            )
            conn.commit()

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
        now_str = get_utc_timestamp()
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
        utc_now = datetime.now(timezone.utc)
        utc_str = get_utc_timestamp()
        actual_bytes = bytes_count if bytes_count is not None else (bytes_affected or 0)
        label = ACTION_LABELS.get(action_type, action_type)

        with self._get_connection() as conn:
            row = conn.execute("SELECT COALESCE(MAX(rowid), 0) + 1 AS next_id FROM operations_history").fetchone()
            next_id = row["next_id"] if row else 1
            entry_id = f"hist_{utc_now.strftime('%Y%m%d_%H%M%S_%f')}_{next_id}"

            # Obtener hash de la fila previa para encadenamiento criptográfico HMAC (NIST SSDF PO.4 / Falla 3)
            last_row = conn.execute("SELECT entry_hash FROM operations_history ORDER BY rowid DESC LIMIT 1").fetchone()
            prev_hash = last_row["entry_hash"] if last_row and last_row["entry_hash"] else "GENESIS"

            new_entry = HistoryEntry(
                entry_id=entry_id,
                timestamp=utc_str,
                action_type=action_type,
                action_label=label,
                target_dir=str(Path(target_dir).resolve()),
                files_count=max(0, int(files_count)),
                bytes_count=max(0, int(actual_bytes)),
                details=details,
                prev_hash=prev_hash,
            )

            # Cálculo de entry_hash mediante HMAC-SHA256 con clave secreta
            entry_hash = compute_entry_hmac(
                prev_hash, new_entry.entry_id, new_entry.timestamp, new_entry.action_type,
                new_entry.target_dir, new_entry.files_count, new_entry.bytes_count
            )
            new_entry.entry_hash = entry_hash

            conn.execute(
                """
                INSERT INTO operations_history
                (entry_id, timestamp, action_type, action_label, target_dir, files_count, bytes_count, details, prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    prev_hash,
                    entry_hash,
                )
            )
            conn.commit()

        return new_entry

    def verify_audit_chain_integrity(self) -> tuple[bool, list[str]]:
        """
        Verifica la inmutabilidad y la cadena criptográfica HMAC (hash-chain / tamper-evident)
        de operations_history. Detecta alteraciones, borrados o inserciones manuales (NIST SSDF PO.4 / Falla 3).
        Retorna (is_valid, errors).
        """
        errors = []
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT rowid, entry_id, timestamp, action_type, target_dir, files_count, bytes_count, prev_hash, entry_hash
                FROM operations_history
                ORDER BY rowid ASC
                """
            ).fetchall()

            expected_prev = "GENESIS"
            for r in rows:
                p_hash = r["prev_hash"] or "GENESIS"
                e_hash = r["entry_hash"] or ""

                # Omitir filas legacy sin hash si no se han resellado aún
                if not e_hash:
                    errors.append(f"[HASH VACÍO] Fila rowid={r['rowid']} ({r['entry_id']}): sin entry_hash.")
                    continue

                if p_hash != expected_prev:
                    errors.append(
                        f"[CADENA ROTA] Fila rowid={r['rowid']} ({r['entry_id']}): "
                        f"prev_hash '{p_hash}' no coincide con el hash previo esperado '{expected_prev}'."
                    )

                computed_hash = compute_entry_hmac(
                    p_hash, r["entry_id"], r["timestamp"], r["action_type"],
                    r["target_dir"], r["files_count"], r["bytes_count"]
                )
                if computed_hash != e_hash:
                    errors.append(
                        f"[ADULTERACIÓN DETECTADA] Fila rowid={r['rowid']} ({r['entry_id']}): "
                        f"los datos fueron modificados. Hash almacenado={e_hash}, hash calculado={computed_hash}."
                    )

                expected_prev = e_hash

        return (len(errors) == 0, errors)

    # Alias de compatibilidad (NIST SSDF PO.4)
    record_operation = record_event

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

    def get_timeseries_points(self) -> list[dict[str, Any]]:
        """
        Extrae la serie temporal cronológica desde `operations_history` en SQLite
        calculando la curva acumulada de memoria recuperada a lo largo del tiempo
        para graficar en el panel analítico (`matplotlib` / Tkinter).
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT timestamp, action_type, bytes_count, files_count
                FROM operations_history
                ORDER BY timestamp ASC, rowid ASC
                """
            ).fetchall()

        points: list[dict[str, Any]] = []
        cumulative_bytes = 0
        for idx, r in enumerate(rows, start=1):
            act = r["action_type"]
            b_cnt = int(r["bytes_count"] or 0)
            if act in ("QUARANTINE", "HARDLINK", "TRASH", "PERMANENT"):
                cumulative_bytes += b_cnt
            elif act == "RESTORE":
                cumulative_bytes = max(0, cumulative_bytes - b_cnt)

            ts_raw = str(r["timestamp"] or "")
            short_ts = ts_raw[5:16] if len(ts_raw) >= 16 else f"#{idx}"
            points.append({
                "index": idx,
                "timestamp": ts_raw,
                "label": short_ts,
                "action_type": act,
                "delta_bytes": b_cnt,
                "cumulative_bytes": cumulative_bytes,
                "cumulative_mb": round(cumulative_bytes / (1024.0 ** 2), 3),
                "cumulative_gb": round(cumulative_bytes / (1024.0 ** 3), 4),
            })
        return points

    def clear_hash_cache(self) -> None:
        """Limpia la tabla de caché persistente de hashes."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM file_hash_cache;")
            conn.commit()

    def clear_history(self) -> None:
        with self._get_connection() as conn:
            conn.executescript(
                """
                DELETE FROM operations_history;
                DELETE FROM archivos_evaluados;
                DELETE FROM sesiones_cuarentena;
                DELETE FROM file_hash_cache;
                """
            )
            conn.commit()
        if self.legacy_json_path and self.legacy_json_path.exists():
            self.legacy_json_path.unlink(missing_ok=True)

    def export_history_json(self, output_path: Path | str) -> Path:
        summary = self.get_summary()
        out = Path(output_path).resolve()
        data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
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
