"""
Pruebas Unitarias para el Módulo de Hashing Criptográfico (RF-03, RNF-01)
"""

import unittest
import tempfile
import hashlib
import shutil
from pathlib import Path

from datacleaner.hasher import compute_file_hash

class TestHasher(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="datacleaner_hash_test_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_compute_file_hash_known_value(self):
        """RF-03: Verifica exactitud del hash SHA-256."""
        content = b"DataCleaner Hashing Test Content 12345"
        expected_sha256 = hashlib.sha256(content).hexdigest()

        test_file = Path(self.temp_dir) / "test.bin"
        test_file.write_bytes(content)

        calculated = compute_file_hash(test_file)
        self.assertEqual(calculated, expected_sha256)

    def test_compute_file_hash_large_chunked(self):
        """RNF-01: Verifica lectura por chunks de 64 KB en archivos mayores al chunk."""
        # Archivo de 200 KB (más de 3 chunks de 64 KB)
        pattern = b"0123456789abcdef" * 1024  # 16 KB
        content = pattern * 13                # ~208 KB
        expected_sha256 = hashlib.sha256(content).hexdigest()

        test_file = Path(self.temp_dir) / "large.bin"
        test_file.write_bytes(content)

        # Usar chunk_size de 65536 y de 4096 para comprobar consistencia
        calculated_64k = compute_file_hash(test_file, chunk_size=65536)
        calculated_4k = compute_file_hash(test_file, chunk_size=4096)

        self.assertEqual(calculated_64k, expected_sha256)
        self.assertEqual(calculated_4k, expected_sha256)

    def test_compute_file_hash_missing_file_returns_none(self):
        """Tolerancia a fallos: no lanza excepción si el archivo no existe."""
        missing = Path(self.temp_dir) / "inexistente.bin"
        result = compute_file_hash(missing)
        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main()
