"""
Pruebas de Verificación y Regresión para Fallas Críticas 1 a 6
DataCleaner Hardened Test Suite
"""

import unittest
import tempfile
import shutil
import os
import sys
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch

from datacleaner.security import (
    is_protected_dev_resource,
    STRUCTURAL_MARKER_FILES,
)
from datacleaner.scanner import scan_directory_for_duplicates
from datacleaner.history import (
    CleaningHistoryManager,
    get_utc_timestamp,
    reseal_legacy_audit_chain,
    _harden_file_permissions,
)


class TestFallasFixes(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="datacleaner_fallas_test_")
        self.base_path = Path(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_falla1_protected_dev_resources_and_zero_byte_files(self):
        """Falla 1: Ignora archivos vacíos de 0 bytes y recursos estructurales/entornos virtuales."""
        # 1. Validación de marcadores y carpetas de dependencias
        for marker in STRUCTURAL_MARKER_FILES:
            self.assertTrue(is_protected_dev_resource(Path(marker)))

        venv_sub = Path("env") / "Lib" / "site-packages" / "django" / "models.py"
        self.assertTrue(is_protected_dev_resource(venv_sub))

        normal_file = Path("documentos") / "reporte.docx"
        self.assertFalse(is_protected_dev_resource(normal_file))

        # 2. Escaneo en disco: archivos vacíos (0 bytes) y marcadores
        scan_folder = self.base_path / "scan_dev_test"
        scan_folder.mkdir()
        (scan_folder / "__init__.py").write_bytes(b"")
        (scan_folder / "py.typed").write_bytes(b"")
        (scan_folder / "empty1.dat").write_bytes(b"")
        (scan_folder / "empty2.dat").write_bytes(b"")

        # Dos archivos idénticos NO vacíos para comprobar que el escáner sigue detectando duplicados reales
        real_content = b"Contenido real de prueba de duplicados" * 10
        (scan_folder / "real1.txt").write_bytes(real_content)
        (scan_folder / "real2.txt").write_bytes(real_content)

        # Escaneo por defecto: archivos de 0 bytes y marcadores ignorados
        dups, summary = scan_directory_for_duplicates(scan_folder, include_empty_files=False)
        self.assertEqual(len(dups), 1, "Debe detectar únicamente el duplicado real")
        self.assertEqual(summary.duplicate_groups_count, 1)
        found_paths = [p.name for p in list(dups.values())[0]]
        self.assertIn("real1.txt", found_paths)
        self.assertIn("real2.txt", found_paths)
        self.assertNotIn("empty1.dat", found_paths)
        self.assertNotIn("__init__.py", found_paths)

    def test_falla2_harden_file_permissions_no_shell_injection(self):
        """Falla 2: _harden_file_permissions invoca icacls con lista y shell=False."""
        target_file = self.base_path / "perm_test.sqlite"
        target_file.write_text("sqlite-mock")

        with patch("subprocess.run") as mock_run:
            _harden_file_permissions(target_file)
            if sys.platform == "win32" and os.environ.get("USERNAME"):
                self.assertTrue(mock_run.called)
                args, kwargs = mock_run.call_args
                cmd_list = args[0]
                self.assertIsInstance(cmd_list, list)
                self.assertEqual(cmd_list[0], "icacls")
                self.assertFalse(kwargs.get("shell", True), "Debe invocar con shell=False para prevenir CWE-78")

    def test_falla3_audit_chain_hmac_and_resealing(self):
        """Falla 3: Cadena de auditoría protegida con HMAC-SHA256 y resellado."""
        db_file = self.base_path / "hmac_audit.sqlite"
        mgr = CleaningHistoryManager(storage_path=db_file)

        # Registrar eventos
        e1 = mgr.record_operation("QUARANTINE", self.base_path, 3, 300, "Op 1")
        e2 = mgr.record_operation("HARDLINK", self.base_path, 2, 200, "Op 2")
        self.assertEqual(e1.prev_hash, "GENESIS")
        self.assertEqual(e2.prev_hash, e1.entry_hash)

        # Cadena íntegra
        is_valid, errors = mgr.verify_audit_chain_integrity()
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

        # Simular filas sin sellar / rotas y probar resellado
        with mgr._get_connection() as conn:
            conn.execute("UPDATE operations_history SET entry_hash = '' WHERE entry_id = ?", (e2.entry_id,))
            conn.commit()

        # Debe detectar hash vacío
        is_valid_broken, errs_broken = mgr.verify_audit_chain_integrity()
        self.assertFalse(is_valid_broken)

        # Resellar cadena
        with mgr._get_connection() as conn:
            reseal_legacy_audit_chain(conn)

        is_valid_fixed, errs_fixed = mgr.verify_audit_chain_integrity()
        self.assertTrue(is_valid_fixed)
        self.assertEqual(len(errs_fixed), 0)

    def test_falla4_secure_delete_and_purge_artifacts(self):
        """Falla 4: PRAGMA secure_delete activo y purga de artefactos de prueba con VACUUM."""
        db_file = self.base_path / "secure_del.sqlite"
        mgr = CleaningHistoryManager(storage_path=db_file)

        with mgr._get_connection() as conn:
            row = conn.execute("PRAGMA secure_delete;").fetchone()
            self.assertEqual(row[0], 1, "PRAGMA secure_delete debe estar activo (1)")

            # Insertar registros temporales usando ruta real
            conn.execute(
                "INSERT INTO file_hash_cache (file_path, file_size, mtime, sha256_hash) "
                "VALUES (?, 100, 1.0, 'dummy_hash')",
                (r"C:\Users\Temp\datacleaner_test.tmp",)
            )
            conn.commit()

        # Purgar y verificar que el registro temporal fue removido
        mgr.purge_test_artifacts_and_vacuum()
        with mgr._get_connection() as conn:
            row_check = conn.execute(
                "SELECT COUNT(*) FROM file_hash_cache WHERE file_path LIKE '%Temp%'"
            ).fetchone()
            self.assertEqual(row_check[0], 0)

    def test_falla5_utc_timestamp_consistency(self):
        """Falla 5: Estandarización de timestamps en UTC ISO sin desfase horario."""
        ts_utc = get_utc_timestamp()
        dt_parsed = datetime.strptime(ts_utc, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        now_utc = datetime.now(timezone.utc)
        diff_seconds = abs((now_utc - dt_parsed).total_seconds())
        self.assertLess(diff_seconds, 10, "El timestamp UTC debe coincidir con el reloj UTC actual")

    def test_falla6_cache_race_condition_mitigation(self):
        """Falla 6: get_cached_hash exige validación conjunta de file_size y partial_hash."""
        db_file = self.base_path / "cache_race.sqlite"
        mgr = CleaningHistoryManager(storage_path=db_file)

        test_file = self.base_path / "target.dat"
        test_file.write_bytes(b"A" * 1024)
        st = test_file.stat()

        mgr.set_cached_file_hash(
            file_path=test_file,
            device_id=st.st_dev,
            inode=getattr(st, "st_ino", 0),
            mtime=st.st_mtime,
            file_size=st.st_size,
            partial_hash="part_hash_12345",
            sha256_hash="full_sha256_abcdef",
        )

        # 1. Coincidencia exacta de todos los parámetros -> Retorna hash cacheado
        cached = mgr.get_cached_hash(
            file_path=str(test_file),
            file_size=st.st_size,
            mtime=st.st_mtime,
            current_partial_hash="part_hash_12345",
        )
        self.assertEqual(cached, "full_sha256_abcdef")

        # 2. Si el partial_hash difiere (contenido mutado rápido) -> Retorna None (Miss)
        miss_partial = mgr.get_cached_hash(
            file_path=str(test_file),
            file_size=st.st_size,
            mtime=st.st_mtime,
            current_partial_hash="part_hash_DIFFERENT",
        )
        self.assertIsNone(miss_partial)

        # 3. Si el file_size difiere -> Retorna None (Miss)
        miss_size = mgr.get_cached_hash(
            file_path=str(test_file),
            file_size=9999,
            mtime=st.st_mtime,
            current_partial_hash="part_hash_12345",
        )
        self.assertIsNone(miss_size)


if __name__ == "__main__":
    unittest.main()
