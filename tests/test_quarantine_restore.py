"""
Pruebas Unitarias para Cuarentena (Soft-Delete) y Restauración (RF-06 y Sección 7)
"""

import unittest
import tempfile
import shutil
import json
from pathlib import Path

from datacleaner.scanner import scan_directory_for_duplicates
from datacleaner.reporter import build_audit_plan
from datacleaner.quarantine import (
    quarantine_redundant_files,
    restore_from_quarantine,
    find_quarantine_sessions,
    purge_quarantine_session,
    purge_all_quarantine_sessions,
    delete_redundant_files,
    execute_deletion_plan,
    QuarantineResult,
    RestoreResult,
    DeleteResult
)
from datacleaner.history import (
    CleaningHistoryManager,
    format_bytes_auto,
    format_bytes_with_equivalence,
)

class TestQuarantineAndRestore(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="datacleaner_quar_test_")
        self.base_path = Path(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_quarantine_and_restore_cycle(self):
        """RF-06: Ciclo completo: Detección -> Cuarentena (Soft-Delete) -> Restauración reversible."""
        folder_a = self.base_path / "Proyectos" / "App"
        folder_b = self.base_path / "Downloads"
        folder_a.mkdir(parents=True)
        folder_b.mkdir(parents=True)

        content = b"Binary Payload Example 123456789"
        file_a = folder_a / "codigo.py"
        file_b = folder_b / "codigo_copia.py"

        file_a.write_bytes(content)
        file_b.write_bytes(content)

        # 1. Escanear
        duplicates, summary = scan_directory_for_duplicates(self.base_path)
        self.assertEqual(len(duplicates), 1)

        # 2. Planificar
        plan = build_audit_plan(duplicates, keep_rule="deepest_then_newest")
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["keep"].resolve(), file_a.resolve())
        self.assertEqual(plan[0]["quarantine"][0].resolve(), file_b.resolve())

        # 3. Ejecutar Cuarentena (Soft-Delete)
        quar_res: QuarantineResult = quarantine_redundant_files(self.base_path, plan)
        self.assertEqual(quar_res.total_moved, 1)
        self.assertEqual(quar_res.total_bytes_moved, len(content))

        # Verificar que file_a (conservado) sigue en disco
        self.assertTrue(file_a.exists())
        # Verificar que file_b fue movido de su ubicación original
        self.assertFalse(file_b.exists())

        # Verificar que el manifest.json existe y es válido
        self.assertTrue(quar_res.manifest_path.exists())
        with open(quar_res.manifest_path, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)
        self.assertEqual(manifest_data["total_files"], 1)

        # 4. Restauración
        rest_res: RestoreResult = restore_from_quarantine(quar_res.manifest_path)
        self.assertEqual(rest_res.total_restored, 1)
        self.assertEqual(len(rest_res.errors), 0)

        # Verificar que file_b fue restaurado exactamente a su lugar y con el mismo contenido
        self.assertTrue(file_b.exists())
        self.assertEqual(file_b.read_bytes(), content)

    def test_find_quarantine_sessions_and_folder_removal(self):
        """Verifica el descubrimiento local de sesiones de cuarentena y eliminación de carpeta vacía."""
        folder = self.base_path / "Documentos"
        folder.mkdir(parents=True)
        f1 = folder / "f1.txt"
        f2 = folder / "f2.txt"
        content = b"Duplicado de prueba para sesiones"
        f1.write_bytes(content)
        f2.write_bytes(content)

        duplicates, summary = scan_directory_for_duplicates(self.base_path)
        plan = build_audit_plan(duplicates)
        q_res = quarantine_redundant_files(self.base_path, plan)

        # 1. Escaneo local de sesiones
        sessions = find_quarantine_sessions(self.base_path)
        self.assertEqual(len(sessions), 1)
        s = sessions[0]
        self.assertEqual(s["total_files"], 1)
        self.assertEqual(s["total_bytes"], len(content))
        self.assertIn("quarantine_", s["session_id"])
        self.assertTrue(Path(s["manifest_path"]).exists())

        # 2. Restauración y eliminación de la carpeta de cuarentena vacía
        q_dir = q_res.quarantine_dir
        self.assertTrue(q_dir.exists())

        rest_res = restore_from_quarantine(s["manifest_path"])
        self.assertEqual(rest_res.total_restored, 1)
        self.assertTrue(rest_res.quarantine_folder_removed)
        self.assertFalse(q_dir.exists(), "La carpeta de cuarentena vacía debe ser eliminada tras la restauración completa")

    def test_purge_quarantine_session(self):
        """Opción 1: Verificación de vaciado y purgado de sesiones de cuarentena."""
        folder = self.base_path / "Datos"
        folder.mkdir(parents=True)
        f1 = folder / "a.txt"
        f2 = folder / "b.txt"
        content = b"Contenido para test de purgado"
        f1.write_bytes(content)
        f2.write_bytes(content)

        duplicates, summary = scan_directory_for_duplicates(self.base_path)
        plan = build_audit_plan(duplicates)
        q_res = quarantine_redundant_files(self.base_path, plan)

        self.assertTrue(q_res.quarantine_dir.exists())
        sessions = find_quarantine_sessions(self.base_path)
        self.assertEqual(len(sessions), 1)

        # Purgar la sesión
        success = purge_quarantine_session(q_res.quarantine_dir)
        self.assertTrue(success)
        self.assertFalse(q_res.quarantine_dir.exists())

        # Sesiones restantes deben ser 0
        sessions_after = find_quarantine_sessions(self.base_path)
        self.assertEqual(len(sessions_after), 0)

    def test_purge_quarantine_security_check(self):
        """Seguridad: purge_quarantine_session rechaza carpetas que no son de cuarentena."""
        not_quarantine = self.base_path / "MisDocumentosImportantes"
        not_quarantine.mkdir()
        with self.assertRaises(ValueError):
            purge_quarantine_session(not_quarantine)
        self.assertTrue(not_quarantine.exists())

    def test_direct_delete_permanent(self):
        """Opción 2: Verificación de eliminación permanente directa (unlink/os.remove)."""
        folder = self.base_path / "DirectDelete"
        folder.mkdir(parents=True)
        f1 = folder / "keep.bin"
        f2 = folder / "dup1.bin"
        f3 = folder / "dup2.bin"
        data = b"Raw binary payload"
        f1.write_bytes(data)
        f2.write_bytes(data)
        f3.write_bytes(data)

        duplicates, _ = scan_directory_for_duplicates(self.base_path)
        plan = build_audit_plan(duplicates)

        del_res = execute_deletion_plan(plan, use_trash=False)
        self.assertEqual(del_res.total_deleted, 2)
        self.assertFalse(del_res.used_trash)
        self.assertTrue(plan[0]["keep"].exists(), "El archivo conservado debe permanecer intacto")
        for q in plan[0]["quarantine"]:
            self.assertFalse(q.exists(), "El duplicado redundante debe ser eliminado permanentemente")

    def test_direct_delete_trash(self):
        """Opción 3: Verificación de eliminación hacia la Papelera de Windows (send2trash)."""
        folder = self.base_path / "TrashTest"
        folder.mkdir(parents=True)
        f1 = folder / "keep.txt"
        f2 = folder / "dup.txt"
        f1.write_text("Hello Keep", encoding="utf-8")
        f2.write_text("Hello Keep", encoding="utf-8")

        duplicates, _ = scan_directory_for_duplicates(self.base_path)
        plan = build_audit_plan(duplicates)

        del_res = execute_deletion_plan(plan, use_trash=True)
        self.assertEqual(del_res.total_deleted, 1)
        self.assertTrue(del_res.used_trash)
        self.assertTrue(plan[0]["keep"].exists())
        self.assertFalse(plan[0]["quarantine"][0].exists(), "El duplicado debe haberse trasladado a la papelera")

    def test_purge_all_quarantine_sessions(self):
        """Opción 1: Purgado de múltiples sesiones de cuarentena."""
        q1 = self.base_path / "_quarantine_20261104_100000"
        q2 = self.base_path / "_quarantine_20261104_200000"
        q1.mkdir()
        q2.mkdir()
        (q1 / "manifest.json").write_text("{}", encoding="utf-8")
        (q2 / "manifest.json").write_text("{}", encoding="utf-8")

        count = purge_all_quarantine_sessions(self.base_path)
        self.assertEqual(count, 2)
        self.assertFalse(q1.exists())
        self.assertFalse(q2.exists())

    def test_unit_conversions_mb_to_gb_and_equivalences(self):
        """Verifica la conversión dinámica de unidades (B -> KB -> MB -> GB -> TB) y equivalencias."""
        # 500 MB debe mostrarse en MB en modo AUTO
        bytes_500mb = 500 * 1024 * 1024
        self.assertEqual(format_bytes_auto(bytes_500mb, "AUTO"), "500.00 MB")
        self.assertIn("GB", format_bytes_with_equivalence(bytes_500mb))

        # 1015 MB (>= 1000 MB) o 2.5 GB debe convertirse automáticamente a GB sin quedarse en miles de MB
        bytes_1015mb = 1015 * 1024 * 1024
        auto_1015 = format_bytes_auto(bytes_1015mb, "AUTO")
        self.assertTrue(auto_1015.endswith("GB"), f"Se esperaba GB pero se obtuvo: {auto_1015}")

        bytes_2_5gb = int(2.5 * (1024 ** 3))
        self.assertEqual(format_bytes_auto(bytes_2_5gb, "AUTO"), "2.50 GB")
        self.assertEqual(format_bytes_auto(bytes_2_5gb, "MB"), "2,560.00 MB")
        self.assertEqual(format_bytes_auto(bytes_2_5gb, "GB"), "2.50 GB")
        self.assertIn("2.50 GB", format_bytes_with_equivalence(bytes_2_5gb))
        self.assertIn("2,560.00 MB", format_bytes_with_equivalence(bytes_2_5gb))

    def test_cleaning_history_manager(self):
        """Verifica el registro acumulativo de redundancias limpiadas y memoria recuperada."""
        hist_file = self.base_path / "test_history.json"
        mgr = CleaningHistoryManager(storage_path=hist_file)

        # 1. Aislamiento en cuarentena de 600 MB (3 archivos)
        b_600mb = 600 * (1024 ** 2)
        mgr.record_event("QUARANTINE", str(self.base_path), 3, b_600mb, "Sesión 1")

        # 2. Envío a Papelera de 650 MB (2 archivos) -> Acumulado = 1250 MB (~1.22 GB)
        b_650mb = 650 * (1024 ** 2)
        mgr.record_event("TRASH", str(self.base_path), 2, b_650mb, "Papelera")

        summary = mgr.get_summary()
        self.assertEqual(summary.total_files_cleaned, 5)
        self.assertEqual(summary.total_bytes_recovered, b_600mb + b_650mb)
        # Al superar 1 GB, la conversión automática entrega GB:
        self.assertTrue(format_bytes_auto(summary.total_bytes_recovered).endswith("GB"))

        # 3. Purgar la cuarentena de 600 MB no duplica el espacio recuperado, pero suma al purgado definitivo
        mgr.record_event("PURGE", str(self.base_path), 3, b_600mb, "Purga Sesión 1")
        summary_after_purge = mgr.get_summary()
        self.assertEqual(summary_after_purge.total_bytes_recovered, b_600mb + b_650mb)
        self.assertEqual(summary_after_purge.total_bytes_purged, b_600mb)


if __name__ == "__main__":
    unittest.main()
