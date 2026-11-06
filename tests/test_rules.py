"""
Pruebas Unitarias para Reglas de Permanencia (Keep Rules) - Sección 7
"""

import unittest
import tempfile
import time
import os
import shutil
from pathlib import Path

from datacleaner.rules import select_file_to_keep, KeepRule

class TestKeepRules(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="datacleaner_rules_test_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_depth_criterion_prefers_deeper_clean_structure(self):
        """Sección 7: Criterio de profundidad prefiere ruta más estructurada."""
        shallow_file = Path(self.temp_dir) / "doc.pdf"
        deep_dir = Path(self.temp_dir) / "Proyectos" / "Finanzas" / "Reportes"
        deep_dir.mkdir(parents=True)
        deep_file = deep_dir / "doc.pdf"

        shallow_file.write_text("contenido")
        deep_file.write_text("contenido")

        kept, to_quarantine = select_file_to_keep(
            [shallow_file, deep_file],
            rule=KeepRule.DEEPEST_THEN_NEWEST
        )

        self.assertEqual(kept, deep_file)
        self.assertEqual(to_quarantine, [shallow_file])

    def test_cleanliness_penalizes_temp_and_downloads(self):
        """Sección 7: Descargas y carpetas temporales son penalizadas frente a carpetas de proyectos."""
        downloads_dir = Path(self.temp_dir) / "Downloads"
        downloads_dir.mkdir()
        download_file = downloads_dir / "reporte.xlsx"

        docs_dir = Path(self.temp_dir) / "Documentos"
        docs_dir.mkdir()
        docs_file = docs_dir / "reporte.xlsx"

        download_file.write_text("datos")
        docs_file.write_text("datos")

        kept, to_quarantine = select_file_to_keep(
            [download_file, docs_file],
            rule=KeepRule.DEEPEST_THEN_NEWEST
        )

        self.assertEqual(kept, docs_file)
        self.assertEqual(to_quarantine, [download_file])

    def test_mtime_criterion_newest_vs_oldest(self):
        """Sección 7: Criterio de antigüedad/modificación."""
        dir_a = Path(self.temp_dir) / "CarpetaA"
        dir_b = Path(self.temp_dir) / "CarpetaB"
        dir_a.mkdir()
        dir_b.mkdir()

        file_old = dir_a / "archivo.txt"
        file_new = dir_b / "archivo.txt"

        file_old.write_text("mismo texto")
        time.sleep(0.05)
        file_new.write_text("mismo texto")

        # Modificar fechas explícitamente para garantizar diferencia
        now = time.time()
        os.utime(file_old, (now - 100, now - 100))
        os.utime(file_new, (now, now))

        # Regla: Newest
        kept_new, quar_new = select_file_to_keep([file_old, file_new], rule=KeepRule.NEWEST_ONLY)
        self.assertEqual(kept_new, file_new)
        self.assertEqual(quar_new, [file_old])

        # Regla: Oldest
        kept_old, quar_old = select_file_to_keep([file_old, file_new], rule=KeepRule.OLDEST_ONLY)
        self.assertEqual(kept_old, file_old)
        self.assertEqual(quar_old, [file_new])

if __name__ == "__main__":
    unittest.main()
