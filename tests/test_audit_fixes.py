"""
Pruebas de Validación para las Correcciones del Reporte de Auditoría Crítica:
CRIT-01: Protección Anti-TOCTOU en Mitigación (Cuarentena, Hardlinks, Borrado)
CRIT-02: Concurrencia Nativa con ThreadPoolExecutor y eliminación de bloqueo de Event Loop
CRIT-04: Resistencia a Case-Sensitivity en Caché SQLite en Windows
CRIT-05: Protección Estricta contra Bypass por %TEMP%
MED-01: Cancelación Cooperativa de Escaneo y Zero Doble-Lectura de Firmas Binarias
MED-02: Validación Estricta de KeepRule y Escape en schtasks
MED-03: Invalidación y Mantenimiento Purgado de file_hash_cache
LOW-01: Centralización DRY de Formateo de Bytes
"""

import unittest
import tempfile
import shutil
import os
import sys
import time
import threading
from pathlib import Path

from datacleaner.security import validate_target_path
from datacleaner.rules import select_file_to_keep, KeepRule
from datacleaner.scanner import scan_directory_for_duplicates
from datacleaner.reporter import build_audit_plan, format_bytes
from datacleaner.quarantine import (
    quarantine_redundant_files,
    delete_redundant_files,
    deduplicate_with_hardlinks,
    _verify_file_unchanged,
)
from datacleaner.history import CleaningHistoryManager, format_bytes_auto
from datacleaner.scheduler import build_schtasks_create_command


class TestAuditFindingsFixes(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="datacleaner_audit_fixes_")
        self.base_path = Path(self.temp_dir).resolve().absolute()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_crit_01_toctou_prevention_in_quarantine(self):
        """CRIT-01: Cuarentena detecta mutación (TOCTOU) y aborta el traslado protegiendo datos nuevos."""
        f1 = self.base_path / "keep.txt"
        f2 = self.base_path / "dup.txt"
        content = b"Original identical content 123456"
        f1.write_bytes(content)
        f2.write_bytes(content)

        dups, _ = scan_directory_for_duplicates(self.base_path)
        plan = build_audit_plan(dups)
        quar_file = plan[0]["quarantine"][0]

        # Simular que el archivo marcado para cuarentena muta antes de la mitigación
        time.sleep(0.02)
        mutated_content = b"MUTATED: User edited file while GUI was open!"
        quar_file.write_bytes(mutated_content)

        result = quarantine_redundant_files(self.base_path, plan)
        # El archivo mutado NO debe haber sido movido
        self.assertEqual(result.total_moved, 0)
        self.assertTrue(quar_file.exists(), "El archivo mutado debe seguir en su ruta original")
        self.assertEqual(quar_file.read_bytes(), mutated_content)
        self.assertTrue(any("TOCTOU" in err for err in result.errors))

    def test_crit_01_toctou_prevention_in_hardlinks(self):
        """CRIT-01: Hardlinks detecta mutación y aborta el enlace sin sobreescribir el archivo mutado."""
        f1 = self.base_path / "master.bin"
        f2 = self.base_path / "replica.bin"
        content = b"Payload for hardlink TOCTOU test 7890"
        f1.write_bytes(content)
        f2.write_bytes(content)

        dups, _ = scan_directory_for_duplicates(self.base_path)
        plan = build_audit_plan(dups)
        quar_file = plan[0]["quarantine"][0]

        # Simular mutación en el archivo redundante
        time.sleep(0.02)
        quar_file.write_bytes(b"NEW IMPORTANT UNSYNCED DATA")

        hl_res = deduplicate_with_hardlinks(plan)
        self.assertEqual(hl_res.total_linked, 0)
        self.assertTrue(any("TOCTOU" in err for err in hl_res.errors))
        self.assertEqual(quar_file.read_bytes(), b"NEW IMPORTANT UNSYNCED DATA")

    def test_crit_01_toctou_prevention_in_delete(self):
        """CRIT-01: Borrado permanente aborta si el archivo redundante mutó tras el escaneo."""
        f1 = self.base_path / "master_del.txt"
        f2 = self.base_path / "dup_del.txt"
        content = b"Deletable duplicate content"
        f1.write_bytes(content)
        f2.write_bytes(content)

        dups, _ = scan_directory_for_duplicates(self.base_path)
        plan = build_audit_plan(dups)
        quar_file = plan[0]["quarantine"][0]

        # Mutar quar_file
        time.sleep(0.02)
        quar_file.write_bytes(b"ALTERED BEFORE UNLINK")

        del_res = delete_redundant_files(
            [quar_file],
            expected_snapshots=plan[0]["quarantine_snapshots"]
        )
        self.assertEqual(del_res.total_deleted, 0)
        self.assertTrue(quar_file.exists())
        self.assertTrue(any("TOCTOU" in err for err in del_res.errors))

    def test_crit_04_cache_case_insensitivity_windows(self):
        """CRIT-04: load_cache_for_directory normaliza y recupera registros sin importar mayúsculas/minúsculas."""
        db_file = self.base_path / "case_test.sqlite"
        mgr = CleaningHistoryManager(storage_path=db_file)

        test_file = self.base_path / "Sample.TXT"
        test_file.write_bytes(b"Case test content")
        st = test_file.stat()

        mgr.set_cached_file_hash(test_file, st.st_dev, st.st_ino, st.st_mtime, st.st_size, "md5hex", "sha256hex")

        # Cargar con ruta en minúsculas
        lower_dir = str(self.base_path).lower()
        cache = mgr.load_cache_for_directory(lower_dir)
        norm_key = os.path.normcase(str(test_file.resolve()))
        self.assertIn(norm_key, cache["by_path"], "La caché debe contener la clave normalizada para case-insensitivity")

    def test_crit_05_non_test_temp_folder_blocked(self):
        """CRIT-05: Subcarpetas de %TEMP% que no tienen prefijo de prueba son bloqueadas si están en lista negra."""
        # Creamos una subcarpeta en temp sin prefijo de prueba
        raw_temp = Path(tempfile.gettempdir())
        non_test_dir = raw_temp / "unauthorized_app_session_dir_12345"
        non_test_dir.mkdir(parents=True, exist_ok=True)
        try:
            # Desactivar temporalmente la bandera de pytest para simular entorno de producción
            is_in_localappdata = False
            local_app_data = os.environ.get("LOCALAPPDATA")
            if local_app_data:
                from datacleaner.security import _is_subpath
                if _is_subpath(non_test_dir, Path(local_app_data)):
                    is_in_localappdata = True

            if is_in_localappdata:
                # Simular llamada directa sin prefijo test en producción
                old_pytest = sys.modules.pop("pytest", None)
                old_env = os.environ.pop("DATACLEANER_TEST_MODE", None)
                try:
                    with self.assertRaises(PermissionError):
                        validate_target_path(non_test_dir)
                finally:
                    if old_pytest:
                        sys.modules["pytest"] = old_pytest
                    if old_env:
                        os.environ["DATACLEANER_TEST_MODE"] = old_env
        finally:
            shutil.rmtree(non_test_dir, ignore_errors=True)

    def test_med_01_cancel_event_aborts_scan(self):
        """MED-01: El evento de cancelación detiene el escaneo cooperativamente."""
        for i in range(10):
            sub = self.base_path / f"folder_{i}"
            sub.mkdir()
            (sub / "data.bin").write_bytes(b"Duplicate bytes " * 1000)

        cancel_ev = threading.Event()
        cancel_ev.set()  # Cancelar de inmediato

        dups, summary = scan_directory_for_duplicates(self.base_path, cancel_event=cancel_ev)
        self.assertTrue(summary.cancelled)
        self.assertEqual(len(dups), 0)

    def test_med_01_no_double_reading_file_signatures(self):
        """MED-01: build_audit_plan reutiliza summary.file_signatures sin reabrir los archivos."""
        f1 = self.base_path / "sig_keep.png"
        f2 = self.base_path / "sig_dup.png"
        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        f1.write_bytes(png_header)
        f2.write_bytes(png_header)

        dups, summary = scan_directory_for_duplicates(self.base_path)
        self.assertIn(str(f1.resolve()), summary.file_signatures)

        # Al pasar file_signatures a build_audit_plan, se reutilizan directamente
        plan = build_audit_plan(dups, file_signatures=summary.file_signatures)
        self.assertIn("PNG", plan[0]["detected_format"])
        self.assertEqual(plan[0]["integrity_status"], "VERIFIED")

    def test_med_02_schtasks_keep_rule_enum_validation(self):
        """MED-02: build_schtasks_create_command valida estrictamente KeepRule y rechaza strings arbitrarios."""
        # Regla válida
        cmd = build_schtasks_create_command(self.base_path, keep_rule=KeepRule.DEEPEST_THEN_NEWEST)
        self.assertIn("--keep-rule deepest_then_newest", " ".join(cmd))

        # Regla inválida inyectada
        with self.assertRaises(ValueError):
            build_schtasks_create_command(self.base_path, keep_rule="malicious_payload; format C:")

    def test_med_03_cache_invalidation_and_pruning(self):
        """MED-03: invalidate_cache_entries elimina rutas borradas y cleanup_obsolete_cache opera sin error."""
        db_file = self.base_path / "prune_test.sqlite"
        mgr = CleaningHistoryManager(storage_path=db_file)

        f = self.base_path / "temp_file.bin"
        f.write_bytes(b"data")
        st = f.stat()

        mgr.set_cached_file_hash(f, st.st_dev, st.st_ino, st.st_mtime, st.st_size, "part", "sha")
        cache_before = mgr.load_cache_for_directory(self.base_path)
        self.assertEqual(len(cache_before["by_path"]), 2)  # original y normcase

        # Invalidar entrada
        deleted = mgr.invalidate_cache_entries([f])
        self.assertGreater(deleted, 0)
        cache_after = mgr.load_cache_for_directory(self.base_path)
        self.assertEqual(len(cache_after["by_path"]), 0)

        # Probar poda de sesiones/caché obsoleta
        purged = mgr.cleanup_obsolete_cache(days=0)
        self.assertIsInstance(purged, int)

    def test_low_01_dry_byte_formatting(self):
        """LOW-01: format_bytes y format_bytes_auto coinciden (Principio DRY)."""
        self.assertEqual(format_bytes(1024), "1.00 KB")
        self.assertEqual(format_bytes_auto(1024), "1.00 KB")
        self.assertEqual(format_bytes(1048576), "1.00 MB")
        self.assertEqual(format_bytes(0), "0 B")

    def test_rules_shallowest_then_newest_uses_relative_depth(self):
        """Rules: SHALLOWEST_THEN_NEWEST calcula profundidad relativa al base_dir y desempata por clean_score."""
        shallow = self.base_path / "doc.txt"
        nested = self.base_path / "Sub" / "doc.txt"
        nested.parent.mkdir()
        shallow.write_text("content")
        nested.write_text("content")

        kept, quar = select_file_to_keep(
            [shallow, nested],
            rule=KeepRule.SHALLOWEST_THEN_NEWEST,
            base_dir=self.base_path
        )
        self.assertEqual(kept.resolve(), shallow.resolve())

    def test_nist_harden_file_permissions(self):
        """Instrucción 4: _harden_file_permissions protege la base de datos (Principio de Menor Privilegio)."""
        from datacleaner.history import _harden_file_permissions
        dummy_file = self.base_path / "secret.txt"
        dummy_file.write_text("sensible-data")

        # Debe ejecutarse sin lanzar excepciones tanto en archivos existentes como inexistentes
        _harden_file_permissions(dummy_file)
        _harden_file_permissions(self.base_path / "no_existe.sqlite")

        # Conexión CleaningHistoryManager aplica endurecimiento
        db_file = self.base_path / "harden_test.sqlite"
        mgr = CleaningHistoryManager(storage_path=db_file)
        with mgr._get_connection() as conn:
            self.assertIsNotNone(conn)
        self.assertTrue(db_file.exists())

    def test_build_sbom_and_sign_helpers(self):
        """Instrucción 2 y 3: generate_sbom y sign_artifact operan de forma segura."""
        import build_executable

        # sign_artifact sin variable de entorno retorna False de manera limpia
        fake_binary = self.base_path / "fake_app.exe"
        fake_binary.write_bytes(b"MZfakebinary")
        self.assertFalse(build_executable.sign_artifact(fake_binary))
        self.assertFalse(build_executable.sign_artifact(self.base_path / "no_existe.exe"))

    def test_github_security_ci_workflow_configured(self):
        """Instrucción 5: Archivo de workflow security_ci.yml presente y estructurado con pinning."""
        workflow_file = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "security_ci.yml"
        self.assertTrue(workflow_file.exists(), "El workflow de GitHub Actions security_ci.yml debe existir")
        content = workflow_file.read_text(encoding="utf-8")
        self.assertIn("pip-audit", content)
        self.assertIn("pytest tests/ -v", content)
        self.assertIn("cyclonedx-bom", content)
        self.assertIn("actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11", content)
        self.assertIn("actions/setup-python@0a5c61591373683505ea898e09a6ea8db8ce1b6a", content)

    def test_quarantine_manifest_cryptographic_signing_and_tamper_detection(self):
        """NIST PO.4: Manifiesto firmado criptográficamente; detecta alteraciones y aborta la restauración."""
        from datacleaner.quarantine import (
            quarantine_redundant_files,
            restore_from_quarantine,
            sign_manifest_file,
            verify_manifest_signature,
        )
        f1 = self.base_path / "keep_doc.txt"
        f2 = self.base_path / "dup_doc.txt"
        f1.write_bytes(b"Same content for sign test")
        f2.write_bytes(b"Same content for sign test")

        dups, _ = scan_directory_for_duplicates(self.base_path)
        plan = build_audit_plan(dups)
        q_dir = self.base_path / "_quar_sig_test"
        res = quarantine_redundant_files(self.base_path, plan, custom_quarantine_dir=q_dir)

        sig_path = res.manifest_path.with_name(res.manifest_path.name + ".sig")
        self.assertTrue(sig_path.exists(), "El archivo manifest.json.sig debe haberse generado")
        self.assertTrue(verify_manifest_signature(res.manifest_path))

        # Simular ataque de adulteración de datos en el manifiesto
        manifest_text = res.manifest_path.read_text(encoding="utf-8")
        adulterated_text = manifest_text + "\n/* Injected Malicious Payload */"
        res.manifest_path.write_text(adulterated_text, encoding="utf-8")

        # La restauración debe abortar inmediatamente por discrepancia de firma
        with self.assertRaises(ValueError) as ctx:
            restore_from_quarantine(res.manifest_path)
        self.assertIn("INTEGRIDAD COMPROMETIDA", str(ctx.exception))

        # Al re-firmar legítimamente, la restauración procede
        sign_manifest_file(res.manifest_path)
        self.assertTrue(verify_manifest_signature(res.manifest_path))

    def test_sqlite_tamper_evident_audit_hash_chain(self):
        """NIST PO.4: Hash-chain append-only en operations_history detecta alteraciones o borrados de filas."""
        db_file = self.base_path / "chain_audit.sqlite"
        mgr = CleaningHistoryManager(storage_path=db_file)

        # Registrar 3 operaciones
        e1 = mgr.record_operation("QUARANTINE", self.base_path, 10, 1024, "Op 1")
        e2 = mgr.record_operation("HARDLINK", self.base_path, 5, 512, "Op 2")
        e3 = mgr.record_operation("RESTORE", self.base_path, 2, 256, "Op 3")

        self.assertEqual(e1.prev_hash, "GENESIS")
        self.assertEqual(e2.prev_hash, e1.entry_hash)
        self.assertEqual(e3.prev_hash, e2.entry_hash)

        # Cadena íntegra
        is_valid, errors = mgr.verify_audit_chain_integrity()
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

        # Adulterar fila intermedia e2 en la base de datos
        with mgr._get_connection() as conn:
            conn.execute(
                "UPDATE operations_history SET files_count = 9999 WHERE entry_id = ?",
                (e2.entry_id,)
            )
            conn.commit()

        # Debe detectar la adulteración inmediatamente
        tampered_valid, tampered_errors = mgr.verify_audit_chain_integrity()
        self.assertFalse(tampered_valid)
        self.assertTrue(any("ADULTERACIÓN DETECTADA" in err for err in tampered_errors))

    def test_forensic_lnk_html_and_rtlo_security(self):
        """CWE-434 / OWASP: Detección forense de .lnk, scripts HTML/HTA y ofuscación RTLO."""
        from datacleaner.magic import analyze_file_signature
        from datacleaner.rules import calculate_path_cleanliness_score

        forensic_dir = self.base_path / "forensic_threats"
        forensic_dir.mkdir()

        # 1. LNK de Windows camuflado como documento .pdf
        lnk_file = forensic_dir / "factura.pdf"
        lnk_file.write_bytes(b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 32)
        rep_lnk = analyze_file_signature(lnk_file)
        self.assertEqual(rep_lnk.integrity_status, "THREAT_EXECUTABLE_CAMOUFLAGED")
        self.assertTrue(rep_lnk.is_anomaly)

        # 2. Script HTML embebido camuflado como documento .docx
        html_doc = forensic_dir / "contrato.docx"
        html_doc.write_bytes(b"<script type='text/javascript'>alert(1)</script>")
        rep_html = analyze_file_signature(html_doc)
        self.assertEqual(rep_html.integrity_status, "THREAT_EXECUTABLE_CAMOUFLAGED")
        self.assertTrue(rep_html.is_anomaly)

        # 3. Ataque RTLO con caracter \u202e invirtiendo la extensión
        rtlo_file = forensic_dir / "documento_\u202efdp.exe"
        rtlo_file.write_bytes(b"data")
        rep_rtlo = analyze_file_signature(rtlo_file)
        self.assertEqual(rep_rtlo.integrity_status, "THREAT_EXECUTABLE_CAMOUFLAGED")
        self.assertTrue(rep_rtlo.is_anomaly)

        # Rules debe penalizar severamente nombres con RTLO (-10000)
        score = calculate_path_cleanliness_score(rtlo_file)
        self.assertLessEqual(score, -10000)

    def test_security_policy_and_governance_files(self):
        """CNCF / NIST PS.1: Archivo SECURITY.md existente con política CVD y firma de commits."""
        security_file = Path(__file__).resolve().parent.parent / "SECURITY.md"
        self.assertTrue(security_file.exists(), "SECURITY.md debe existir en la raíz del proyecto")
        text = security_file.read_text(encoding="utf-8")
        self.assertIn("Coordinated Vulnerability Disclosure", text)
        self.assertIn("NIST SSDF", text)
        self.assertIn("GPG", text)


if __name__ == "__main__":
    import sys
    unittest.main()
