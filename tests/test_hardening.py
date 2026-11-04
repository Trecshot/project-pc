"""
Pruebas de Hardening y Puntos Críticos de Seguridad
Compatible con pytest y unittest.
Verifica:
1. Ignorado de Enlaces Simbólicos (Symlinks y Junctions)
2. Prevención de saturación de descriptores (safe workers)
3. Prevención de colisión de nombres en cuarentena (Zero Overwrite)
4. Normalización estricta de rutas relativas complejas y caracteres especiales
5. Serialización UTF-8 íntegra con acentos y caracteres en español
"""

import unittest
import tempfile
import shutil
import json
import os
from pathlib import Path

from datacleaner.security import validate_target_path, SYSTEM_BLACKLIST
from datacleaner.hasher import get_safe_worker_count, compute_file_hash
from datacleaner.scanner import scan_directory_for_duplicates, is_symlink_or_junction
from datacleaner.quarantine import quarantine_redundant_files, restore_from_quarantine
from datacleaner.reporter import build_audit_plan

class TestHardeningAndSecurity(unittest.TestCase):
    def setUp(self):
        # Directorio temporal estrictamente aislado
        self.test_dir = tempfile.mkdtemp(prefix="datacleaner_hardening_")
        self.base_path = Path(self.test_dir).resolve().absolute()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_safe_worker_count_limits_file_descriptors(self):
        """Hardening hasher.py: Control riguroso de concurrencia para evitar Too many open files."""
        # Valores por defecto o no especificados se regulan entre 2 y 8
        self.assertLessEqual(get_safe_worker_count(None), 8)
        self.assertGreaterEqual(get_safe_worker_count(None), 2)
        # Valores excesivos se limitan a un tope seguro
        self.assertEqual(get_safe_worker_count(999), 16)
        self.assertEqual(get_safe_worker_count(-5), 1)

    def test_relative_path_normalization_and_special_chars(self):
        """Hardening security.py: Normalización de referencias relativas complejas (./../)."""
        sub = self.base_path / "carpeta1" / "subcarpeta"
        sub.mkdir(parents=True)
        # Ruta con redundancias relativas "./../" y barras mixtas
        complex_path = str(self.base_path) + "/carpeta1/../carpeta1/subcarpeta/./"
        validated = validate_target_path(complex_path)
        self.assertEqual(validated, sub.resolve().absolute())

    def test_quarantine_name_collision_avoidance(self):
        """Hardening quarantine.py: Dos archivos con mismo nombre en rutas diferentes no se sobrescriben."""
        dir_a = self.base_path / "A"
        dir_b = self.base_path / "B"
        dir_a.mkdir()
        dir_b.mkdir()

        content = b"Contenido identico de prueba 12345"
        file_a = dir_a / "documento.pdf"
        file_b = dir_b / "documento.pdf"
        file_a.write_bytes(content)
        file_b.write_bytes(content)

        duplicates, summary = scan_directory_for_duplicates(self.base_path)
        plan = build_audit_plan(duplicates)

        # Forzar un plan donde ambos archivos intenten moverse al mismo directorio de destino
        quarantine_dir = self.base_path / "_quarantine_test"
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # Simular conflicto forzado: ambos archivos van a la misma ruta relativa en cuarentena
        forced_plan = [{
            "hash": list(duplicates.keys())[0],
            "keep": file_a,
            "quarantine": [file_a, file_b]  # Ambos se envían a cuarentena
        }]

        result = quarantine_redundant_files(self.base_path, forced_plan, custom_quarantine_dir=quarantine_dir)
        
        # Ambos deben haberse movido sin que el segundo sobrescriba al primero
        self.assertEqual(result.total_moved, 2)
        quarantined_files = list(quarantine_dir.rglob("*.pdf"))
        self.assertEqual(len(quarantined_files), 2)
        # Comprobar que los contenidos de ambos archivos en cuarentena están intactos
        for qf in quarantined_files:
            self.assertEqual(qf.read_bytes(), content)

    def test_utf8_manifest_integrity_with_spanish_accents(self):
        """Hardening quarantine.py / reporter.py: Codificación UTF-8 explícita con caracteres especiales."""
        spanish_dir = self.base_path / "Diseño y Producción 2026" / "Año Nuevo"
        spanish_dir.mkdir(parents=True)

        content = b"Texto con codificacion especial UTF-8"
        file1 = spanish_dir / "cotización_señalética_diseño.txt"
        file2 = spanish_dir / "copia_de_cotización.txt"

        file1.write_bytes(content)
        file2.write_bytes(content)

        duplicates, summary = scan_directory_for_duplicates(self.base_path)
        plan = build_audit_plan(duplicates)
        result = quarantine_redundant_files(self.base_path, plan)

        # Leer el manifiesto JSON asegurando que se escribió en UTF-8 y se recuperan los acentos
        with open(result.manifest_path, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)

        self.assertEqual(len(manifest_data["items"]), 1)
        item = manifest_data["items"][0]
        self.assertIn("cotización", item["original_path"])
        self.assertIn("Diseño y Producción 2026", item["original_path"])

        # Restaurar y verificar que el archivo con caracteres en español vuelve exactamente igual
        restore_result = restore_from_quarantine(result.manifest_path)
        self.assertEqual(restore_result.total_restored, 1)
        self.assertTrue(Path(item["original_path"]).exists())

    def test_symlinks_ignored_in_scanner(self):
        """Hardening scanner.py: Ignorar enlaces simbólicos para prevenir bucles infinitos."""
        real_dir = self.base_path / "real_dir"
        real_dir.mkdir()
        real_file = real_dir / "real_file.bin"
        real_file.write_bytes(b"Datos reales")

        symlink_dir = self.base_path / "link_dir"
        try:
            os.symlink(real_dir, symlink_dir, target_is_directory=True)
            has_symlinks = True
        except (OSError, NotImplementedError):
            # En Windows sin modo desarrollador, os.symlink puede requerir privilegios elevados
            has_symlinks = False

        if has_symlinks:
            self.assertTrue(is_symlink_or_junction(symlink_dir))
            duplicates, summary = scan_directory_for_duplicates(self.base_path)
            # El archivo en el symlink_dir no debe contarse por duplicado
            self.assertEqual(summary.total_files_scanned, 1)

if __name__ == "__main__":
    unittest.main()
