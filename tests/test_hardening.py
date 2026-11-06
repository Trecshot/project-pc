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

    def test_send2trash_fallback_raises_runtime_error(self):
        """Hardening quarantine.py: Si use_trash=True y HAS_SEND2TRASH=False, abortar con RuntimeError."""
        import datacleaner.quarantine as q_mod
        test_file = self.base_path / "test_safety_trash.txt"
        test_file.write_text("Dato que no debe ser destruido")

        orig_has = q_mod.HAS_SEND2TRASH
        try:
            q_mod.HAS_SEND2TRASH = False
            with self.assertRaises(RuntimeError) as ctx:
                q_mod.delete_redundant_files([test_file], use_trash=True)
            self.assertIn("send2trash", str(ctx.exception))
            # Garantizar que el archivo NO fue eliminado de forma permanente accidental
            self.assertTrue(test_file.exists())
        finally:
            q_mod.HAS_SEND2TRASH = orig_has

    def test_scanner_phase2_real_partial_hash_saved_in_sqlite(self):
        """Hardening scanner.py: partial_hash guardado en SQLite debe ser un hash seguro de 32 hex (SHA-256 truncado), no 'md5_edges'."""
        from datacleaner.history import CleaningHistoryManager
        db_path = self.base_path / "cache_integrity_test.sqlite"
        mgr = CleaningHistoryManager(storage_path=db_path)

        dir_test = self.base_path / "cache_check"
        dir_test.mkdir()
        f1 = dir_test / "file1.bin"
        f2 = dir_test / "file2.bin"
        content = b"K" * 150000
        f1.write_bytes(content)
        f2.write_bytes(content)

        dups, summary = scan_directory_for_duplicates(dir_test, history_manager=mgr)
        self.assertEqual(len(dups), 1)

        with mgr._get_connection() as conn:
            rows = conn.execute("SELECT file_path, partial_hash, sha256_hash FROM file_hash_cache").fetchall()
            self.assertGreaterEqual(len(rows), 2)
            for r in rows:
                p_hash = r["partial_hash"]
                self.assertIsNotNone(p_hash)
                self.assertNotEqual(p_hash, "md5_edges", "El partial_hash no debe ser un placeholder 'md5_edges'")
                self.assertEqual(len(p_hash), 32, "El partial_hash debe ser un hash hexadecimal seguro de 32 caracteres (NIST SP 800-131A / FIPS 140-3)")

    def test_rules_cleanliness_no_false_positive_substrings(self):
        """Hardening rules.py: Nombres como Templates o Copyright no deben ser penalizados por contener 'temp' o 'copy'."""
        from datacleaner.rules import calculate_path_cleanliness_score
        templates_path = Path("Templates/project/document.txt")
        temp_path = Path("temp/project/document.txt")
        copyright_path = Path("Copyright/project/document.txt")
        copia_path = Path("copia/project/document.txt")

        score_templates = calculate_path_cleanliness_score(templates_path)
        score_temp = calculate_path_cleanliness_score(temp_path)
        score_copyright = calculate_path_cleanliness_score(copyright_path)
        score_copia = calculate_path_cleanliness_score(copia_path)

        self.assertGreater(score_templates, score_temp)
        self.assertGreater(score_copyright, score_copia)

    def test_iter_directory_files_skips_git_and_protected_dirs(self):
        """Hardening scanner.py: Excluir por defecto .git, node_modules y directorios protegidos de sistema."""
        from datacleaner.scanner import iter_directory_files
        git_dir = self.base_path / ".git" / "objects"
        git_dir.mkdir(parents=True)
        git_file = git_dir / "commit.blob"
        git_file.write_bytes(b"blob data")

        node_dir = self.base_path / "node_modules" / "pkg"
        node_dir.mkdir(parents=True)
        node_file = node_dir / "index.js"
        node_file.write_bytes(b"js data")

        valid_dir = self.base_path / "src"
        valid_dir.mkdir(parents=True)
        valid_file = valid_dir / "app.py"
        valid_file.write_bytes(b"python code")

        scanned = list(iter_directory_files(self.base_path))
        scanned_resolved = [p.resolve() for p in scanned]

        self.assertIn(valid_file.resolve(), scanned_resolved)
        self.assertNotIn(git_file.resolve().as_posix(), [p.as_posix() for p in scanned_resolved])
        self.assertNotIn(node_file.resolve().as_posix(), [p.as_posix() for p in scanned_resolved])

    def test_user_home_allowed_while_appdata_directly_blocked(self):
        """Hardening security.py: C:\\Users\\<Usuario> es permitido mientras que AppData directo es bloqueado."""
        user_home = Path.home()
        validated_home = validate_target_path(user_home)
        self.assertEqual(validated_home, user_home.resolve().absolute())

        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data and Path(local_app_data).exists():
            with self.assertRaises(PermissionError):
                validate_target_path(local_app_data)

    def test_load_cache_for_directory_exact_prefix_no_wildcard_leak(self):
        """Hardening history.py: load_cache_for_directory no debe mezclar C:\\Carpeta con C:\\Carpeta_backup."""
        from datacleaner.history import CleaningHistoryManager
        db_file = self.base_path / "cache_prefix_test.sqlite"
        mgr = CleaningHistoryManager(storage_path=db_file)

        base_a = self.base_path / "proyecto"
        base_b = self.base_path / "proyecto_backup"
        base_a.mkdir()
        base_b.mkdir()

        file_a = base_a / "app.py"
        file_b = base_b / "app.py"
        file_a.write_text("code a")
        file_b.write_text("code b")

        st_a = file_a.stat()
        st_b = file_b.stat()

        mgr.set_cached_file_hash(file_a, st_a.st_dev, st_a.st_ino, st_a.st_mtime, st_a.st_size, "hash_part_a", "hash_sha_a")
        mgr.set_cached_file_hash(file_b, st_b.st_dev, st_b.st_ino, st_b.st_mtime, st_b.st_size, "hash_part_b", "hash_sha_b")

        cache_a = mgr.load_cache_for_directory(base_a)
        self.assertIn(str(file_a.resolve()), cache_a["by_path"])
        self.assertNotIn(str(file_b.resolve()), cache_a["by_path"], "No debe cargar archivos de directorios con prefijo similar")

    def test_reporter_passes_base_dir_to_cleanliness_scoring(self):
        """Hardening reporter.py / rules.py: build_audit_plan propaga base_dir para cálculo relativo."""
        f_dir = self.base_path / "test_base"
        sub_deep = f_dir / "carpeta" / "sub"
        sub_deep.mkdir(parents=True)
        f1 = f_dir / "file.txt"
        f2 = sub_deep / "file.txt"
        f1.write_text("identico")
        f2.write_text("identico")

        dups = {"hash123": [f1, f2]}
        plan = build_audit_plan(dups, keep_rule="deepest_then_newest", base_dir=f_dir)
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["keep"].resolve(), f2.resolve())

    def test_cli_execute_quarantine_records_history_event(self):
        """Hardening cli.py: _execute_quarantine registra el evento en CleaningHistoryManager."""
        from datacleaner.cli import _execute_quarantine
        from datacleaner.history import CleaningHistoryManager
        mgr = CleaningHistoryManager()
        initial_ops = mgr.get_summary().total_operations

        d1 = self.base_path / "cli_d1"
        d2 = self.base_path / "cli_d2"
        d1.mkdir()
        d2.mkdir()
        f1 = d1 / "f.txt"
        f2 = d2 / "f.txt"
        content = b"cli history test content"
        f1.write_bytes(content)
        f2.write_bytes(content)

        dups = {"hash_cli_1": [f1, f2]}
        _execute_quarantine(self.base_path, dups, "deepest_then_newest")

        after_ops = mgr.get_summary().total_operations
        self.assertGreater(after_ops, initial_ops)

if __name__ == "__main__":
    unittest.main()
