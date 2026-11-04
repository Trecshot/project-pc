"""
Pruebas Unitarias para el Motor de Escaneo y Detección de Duplicados (RF-04, RNF-02)
"""

import unittest
import tempfile
import shutil
from pathlib import Path

from datacleaner.scanner import scan_directory_for_duplicates

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="datacleaner_scan_test_")
        self.base_path = Path(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_no_duplicates_returns_empty(self):
        """Si todos los archivos son distintos, no se detectan duplicados."""
        (self.base_path / "f1.txt").write_text("contenido 1")
        (self.base_path / "f2.txt").write_text("contenido 2 con longitud diferente")
        (self.base_path / "f3.txt").write_text("contenido 3 muy diferente")

        duplicates, summary = scan_directory_for_duplicates(self.base_path)
        self.assertEqual(len(duplicates), 0)
        self.assertEqual(summary.duplicate_groups_count, 0)
        self.assertEqual(summary.recoverable_bytes, 0)
        self.assertEqual(summary.total_files_scanned, 3)

    def test_exact_duplicates_detected_across_folders(self):
        """RF-04: Duplicados con diferente nombre en carpetas distintas son identificados."""
        sub1 = self.base_path / "sub1"
        sub2 = self.base_path / "sub2" / "profundo"
        sub1.mkdir(parents=True)
        sub2.mkdir(parents=True)

        content_a = b"Identical Binary Content Alpha" * 50
        content_b = b"Unique Content Beta"

        # Dos copias de Alpha con nombres distintos
        f1 = sub1 / "original_alpha.dat"
        f2 = sub2 / "copia_alpha.dat"
        f1.write_bytes(content_a)
        f2.write_bytes(content_a)

        # Archivo Beta único
        f3 = sub1 / "unico.dat"
        f3.write_bytes(content_b)

        duplicates, summary = scan_directory_for_duplicates(self.base_path)

        self.assertEqual(len(duplicates), 1)
        self.assertEqual(summary.duplicate_groups_count, 1)
        self.assertEqual(summary.total_duplicate_files, 2)
        self.assertEqual(summary.recoverable_bytes, len(content_a))

        # Verificar que el hash de Alpha agrupa a f1 y f2
        hash_key = list(duplicates.keys())[0]
        detected_paths = [p.resolve() for p in duplicates[hash_key]]
        self.assertIn(f1.resolve(), detected_paths)
        self.assertIn(f2.resolve(), detected_paths)

    def test_same_size_different_content_no_false_positive(self):
        """Garantiza que colisiones de tamaño con distinto contenido SHA-256 no se marquen como duplicados."""
        # Dos archivos de exactamente 10 bytes pero diferente contenido
        f1 = self.base_path / "a.txt"
        f2 = self.base_path / "b.txt"
        f1.write_bytes(b"1234567890")
        f2.write_bytes(b"0987654321")

        duplicates, summary = scan_directory_for_duplicates(self.base_path)
        self.assertEqual(len(duplicates), 0)
        self.assertEqual(summary.duplicate_groups_count, 0)

    def test_ignores_quarantine_folders(self):
        """Verifica que las carpetas _quarantine_* no sean escaneadas como duplicados."""
        quar_dir = self.base_path / "_quarantine_20261104_120000"
        quar_dir.mkdir()
        (quar_dir / "aislado.txt").write_text("mismo contenido")

        (self.base_path / "activo.txt").write_text("mismo contenido")

        duplicates, summary = scan_directory_for_duplicates(self.base_path)
        self.assertEqual(len(duplicates), 0)

if __name__ == "__main__":
    unittest.main()
