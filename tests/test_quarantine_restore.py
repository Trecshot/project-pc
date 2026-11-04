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
    QuarantineResult,
    RestoreResult
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

if __name__ == "__main__":
    unittest.main()
