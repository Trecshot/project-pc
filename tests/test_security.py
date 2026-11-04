"""
Pruebas Unitarias para el Módulo de Seguridad y Validación de Rutas (RF-01, RF-02)
"""

import unittest
import tempfile
import shutil
from pathlib import Path

from datacleaner.security import validate_target_path, is_root_directory, SYSTEM_BLACKLIST

class TestSecurity(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="datacleaner_sec_test_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_valid_safe_directory(self):
        """Valida que una carpeta temporal segura pase la verificación."""
        validated = validate_target_path(self.temp_dir)
        self.assertEqual(validated, Path(self.temp_dir).resolve())

    def test_empty_path_raises_value_error(self):
        """Valida que pasar cadena vacía lance ValueError."""
        with self.assertRaises(ValueError):
            validate_target_path("")

    def test_non_existent_path_raises_file_not_found(self):
        """Valida que rutas inexistentes lancen FileNotFoundError."""
        fake_path = Path(self.temp_dir) / "carpeta_que_no_existe_12345"
        with self.assertRaises(FileNotFoundError):
            validate_target_path(fake_path)

    def test_file_instead_of_dir_raises_not_a_directory(self):
        """Valida que indicar un archivo regular cuando se espera directorio lance NotADirectoryError."""
        test_file = Path(self.temp_dir) / "sample.txt"
        test_file.write_text("contenido de prueba")
        with self.assertRaises(NotADirectoryError):
            validate_target_path(test_file, must_be_dir=True)

    def test_root_directory_blocked(self):
        """RF-01: Valida que unidades raíz completas (ej. C:\\ o /) sean bloqueadas."""
        root_path = Path(self.temp_dir).anchor
        self.assertTrue(is_root_directory(Path(root_path)))
        with self.assertRaises(PermissionError) as ctx:
            validate_target_path(root_path)
        self.assertIn("Escaneo de disco completo o partición raíz bloqueado", str(ctx.exception))

    def test_system_blacklist_protection(self):
        """RF-02: Valida que rutas del sistema protegidas lancen PermissionError."""
        for restricted in SYSTEM_BLACKLIST:
            # Solo probar las rutas que existen en este SO
            if restricted.exists():
                with self.assertRaises(PermissionError):
                    validate_target_path(restricted)

if __name__ == "__main__":
    unittest.main()
