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
from datacleaner.hasher import compute_partial_hash
from datacleaner.magic import analyze_file_signature
from datacleaner.quarantine import (
    quarantine_redundant_files,
    restore_from_quarantine,
    find_quarantine_sessions,
    purge_quarantine_session,
    purge_all_quarantine_sessions,
    delete_redundant_files,
    execute_deletion_plan,
    deduplicate_with_hardlinks,
    QuarantineResult,
    RestoreResult,
    DeleteResult,
    HardlinkResult,
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

    def test_multi_stage_hashing_pipeline_o1_ok_on(self):
        """
        Instrucción 1: Verifica el Algoritmo de Dispersión Escalonada (O(1) -> O(k) -> O(n)).
        Dos archivos grandes (> 256 KB) con igual st_size pero distinto primer/último chunk de 64 KB
        deben ser descartados en la Fase 2 (Fast-Hash) sin ejecutar SHA-256 completo (Fase 3).
        """
        stage_dir = self.base_path / "MultiStage"
        stage_dir.mkdir(parents=True)

        f1 = stage_dir / "iso_a.bin"
        f2 = stage_dir / "iso_b.bin"
        # Crear 300 KB con igual centro pero diferente primer/último bloque de 64 KB
        middle = b"M" * (172 * 1024)
        f1.write_bytes(b"A" * 65536 + middle + b"X" * 65536)
        f2.write_bytes(b"B" * 65536 + middle + b"Y" * 65536)

        self.assertNotEqual(compute_partial_hash(f1), compute_partial_hash(f2))

        duplicates, summary = scan_directory_for_duplicates(stage_dir)
        self.assertEqual(len(duplicates), 0)
        self.assertEqual(summary.size_collision_candidates, 2)
        self.assertEqual(summary.partial_hash_evaluated, 2)
        self.assertEqual(summary.partial_hash_discarded, 2)
        self.assertEqual(summary.full_hash_evaluated, 0, "Fase 3 no debe ejecutarse si Fase 2 descarta la colisión")

    def test_magic_numbers_binary_signature_integrity(self):
        """
        Instrucción 2: Verifica Análisis de Integridad por Firmas Binarias (Magic Numbers).
        Detecta documentos PDF genuinos, extensiones manipuladas y ejecutables MZ camuflados.
        """
        magic_dir = self.base_path / "ForensicMagic"
        magic_dir.mkdir(parents=True)

        # 1. PDF genuino (%PDF = 25 50 44 46)
        valid_pdf = magic_dir / "contrato.pdf"
        valid_pdf.write_bytes(b"%PDF-1.7\nContenido PDF genuino")
        rep_pdf = analyze_file_signature(valid_pdf)
        self.assertEqual(rep_pdf.integrity_status, "VERIFIED")
        self.assertEqual(rep_pdf.detected_mime, "application/pdf")
        self.assertTrue(rep_pdf.header_hex.startswith("25 50 44 46"))
        self.assertFalse(rep_pdf.is_anomaly)

        # 2. Extensión ofuscada (.jpg que en realidad contiene %PDF)
        spoofed_jpg = magic_dir / "foto_falsa.jpg"
        spoofed_jpg.write_bytes(b"%PDF-1.7\nContenido PDF con extension JPG")
        rep_spoof = analyze_file_signature(spoofed_jpg)
        self.assertEqual(rep_spoof.integrity_status, "EXTENSION_MISMATCH")
        self.assertTrue(rep_spoof.is_anomaly)

        # 3. Ejecutable PE (MZ = 4D 5A) camuflado como documento .pdf
        camouflaged_exe = magic_dir / "factura_urgente.pdf"
        camouflaged_exe.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00Payload ejecutable")
        rep_threat = analyze_file_signature(camouflaged_exe)
        self.assertEqual(rep_threat.integrity_status, "THREAT_EXECUTABLE_CAMOUFLAGED")
        self.assertTrue(rep_threat.is_anomaly)

    def test_os_level_hardlinks_deduplication(self):
        """
        Instrucción 3: Verifica Deduplicación Transparente mediante Hardlinks (os.link).
        Reemplaza copias redundantes por enlaces físicos al mismo clúster sin romper rutas.
        """
        hl_dir = self.base_path / "HardlinkProject"
        hl_dir.mkdir(parents=True)
        sub_a = hl_dir / "module_a"
        sub_b = hl_dir / "module_b"
        sub_a.mkdir()
        sub_b.mkdir()

        f1 = sub_a / "static_asset.bin"
        f2 = sub_b / "static_asset_copy.bin"
        payload = b"Recurso estatico compartido de 1024 bytes " * 64
        f1.write_bytes(payload)
        f2.write_bytes(payload)

        duplicates, _ = scan_directory_for_duplicates(hl_dir)
        plan = build_audit_plan(duplicates)
        hl_res = deduplicate_with_hardlinks(plan)

        self.assertEqual(hl_res.total_linked, 1)
        self.assertEqual(hl_res.total_bytes_saved, len(payload))
        # Ambos archivos siguen existiendo en sus rutas originales
        self.assertTrue(f1.exists())
        self.assertTrue(f2.exists())
        # Y apuntan exactamente al mismo inodo físico en NTFS/ext4/APFS
        self.assertEqual(f1.stat().st_ino, f2.stat().st_ino)

        # Un segundo escaneo debe reconocer que ya están deduplicados por hardlink
        dups_after, summary_after = scan_directory_for_duplicates(hl_dir)
        self.assertEqual(len(dups_after), 0)
        self.assertEqual(summary_after.already_hardlinked_skipped, 1)

    def test_sqlite_transactional_schema_tables(self):
        """
        Instrucción 4: Verifica que las 3 tablas relacionales SQLite normalizadas
        (sesiones_cuarentena, archivos_evaluados, metricas_recuperacion) operen transaccionalmente.
        """
        db_file = self.base_path / "audit_test.db"
        mgr = CleaningHistoryManager(storage_path=db_file)

        mgr.record_audit_session(
            session_id="sess_20261105_01",
            base_dir=self.base_path,
            keep_rule="deepest_then_newest",
            status="ACTIVE",
            files_count=2,
            bytes_isolated=4096,
            evaluated_files=[
                {
                    "file_path": str(self.base_path / "doc.pdf"),
                    "file_size": 2048,
                    "fast_hash": "abcd1234",
                    "sha256_hash": "ef0123456789",
                    "detected_mime": "application/pdf",
                    "integrity_status": "VERIFIED",
                    "action_taken": "KEEP",
                }
            ]
        )
        mgr.update_quarantine_session_status("sess_20261105_01", "PURGED")

        with mgr._get_connection() as conn:
            sess_row = conn.execute(
                "SELECT status, bytes_isolated FROM sesiones_cuarentena WHERE session_id = ?",
                ("sess_20261105_01",)
            ).fetchone()
            self.assertEqual(sess_row["status"], "PURGED")
            self.assertEqual(sess_row["bytes_isolated"], 4096)

            eval_row = conn.execute(
                "SELECT detected_mime, integrity_status FROM archivos_evaluados WHERE session_id = ?",
                ("sess_20261105_01",)
            ).fetchone()
            self.assertEqual(eval_row["detected_mime"], "application/pdf")
            self.assertEqual(eval_row["integrity_status"], "VERIFIED")

    def test_timeseries_and_scheduler_and_nuitka_spec(self):
        """
        Verifica:
        1. Serie temporal analítica desde SQLite (`get_timeseries_points`) para matplotlib.
        2. Generación de comando `schtasks` (Windows Task Scheduler API).
        3. Especificación de compilación AOT con Nuitka (`get_nuitka_command`).
        """
        from datacleaner.scheduler import build_schtasks_create_command
        from build_executable import get_nuitka_command

        db_file = self.base_path / "ts_test.sqlite"
        mgr = CleaningHistoryManager(storage_path=db_file)
        mgr.record_event("QUARANTINE", str(self.base_path), 4, 10 * 1024 * 1024, "S1")
        mgr.record_event("TRASH", str(self.base_path), 2, 5 * 1024 * 1024, "S2")

        pts = mgr.get_timeseries_points()
        self.assertEqual(len(pts), 2)
        self.assertAlmostEqual(pts[1]["cumulative_mb"], 15.0, places=2)

        sched_cmd = build_schtasks_create_command(self.base_path, schedule_type="WEEKLY", start_time="09:00")
        self.assertIn("schtasks", sched_cmd)
        self.assertIn("/Create", sched_cmd)
        self.assertIn("WEEKLY", sched_cmd)

        nuitka_cmd = get_nuitka_command()
        self.assertIn("--standalone", nuitka_cmd)
        self.assertIn("--onefile", nuitka_cmd)
        self.assertIn("--windows-console-mode=disable", nuitka_cmd)
        self.assertIn("--enable-plugin=tk-inter", nuitka_cmd)

    def test_bloom_filter_probabilistic_ram_optimization(self):
        """
        Mejora 2: Verifica que el Filtro de Bloom opere con cero falsos negativos
        y mantenga una huella de memoria compacta para descarte preliminar.
        """
        from datacleaner.bloom import BloomFilter

        bf = BloomFilter(expected_elements=1000, false_positive_rate=0.01)
        sizes = [1024, 2048, 4096, 8192, 16384, 32768, 65536]
        for s in sizes:
            bf.add(s)

        # Cero falsos negativos: todos los elementos insertados deben responder True
        for s in sizes:
            self.assertTrue(s in bf, f"Tamaño {s} debería estar presente en el Filtro de Bloom")

        # Elemento claramente ausente
        self.assertFalse(99999999 in bf)
        self.assertGreater(bf.memory_bytes, 0)
        self.assertLess(bf.memory_bytes, 50_000, "La huella de memoria debe ser minúscula")

    def test_stateful_caching_sqlite(self):
        """
        Mejora 1: Verifica la Caché de Estado Hashed (Stateful Caching en SQLite O(1)).
        Al re-escanear un directorio sin modificaciones, se reutilizan los hashes evitando lecturas de disco.
        """
        cache_dir = self.base_path / "StatefulCacheTest"
        cache_dir.mkdir(parents=True)
        f1 = cache_dir / "c1.bin"
        f2 = cache_dir / "c2.bin"
        data = b"Stateful Caching Payload Content 12345"
        f1.write_bytes(data)
        f2.write_bytes(data)

        db_file = self.base_path / "cache_test.sqlite"
        custom_mgr = CleaningHistoryManager(storage_path=db_file)

        # Escaneo 1: Cache Miss inicial -> calcula y persiste en SQLite
        dups1, sum1 = scan_directory_for_duplicates(cache_dir, history_manager=custom_mgr)
        self.assertEqual(len(dups1), 1)
        self.assertGreaterEqual(sum1.cache_misses, 2)

        # Escaneo 2: Cache Hit -> recupera desde SQLite sin E/S repetitiva
        dups2, sum2 = scan_directory_for_duplicates(cache_dir, history_manager=custom_mgr)
        self.assertEqual(len(dups2), 1)
        self.assertGreaterEqual(sum2.cache_hits, 2, "El segundo escaneo debe aprovechar los hashes en caché")

    def test_asyncio_aiofiles_pipeline(self):
        """
        Mejora 3: Verifica la lectura y escaneo asíncrono no bloqueante con AsyncIO y aiofiles.
        """
        import asyncio
        from datacleaner.hasher import (
            compute_file_hash,
            compute_partial_hash,
            compute_file_hash_async,
            compute_partial_hash_async,
        )
        from datacleaner.scanner import scan_directory_async

        async_dir = self.base_path / "AsyncIOTest"
        async_dir.mkdir(parents=True)
        t_file = async_dir / "async_sample.dat"
        payload = b"X" * 150000 + b"Y" * 150000
        t_file.write_bytes(payload)

        # Comparar hashes síncronos vs asíncronos bit a bit
        sync_full = compute_file_hash(t_file)
        async_full = asyncio.run(compute_file_hash_async(t_file))
        self.assertEqual(sync_full, async_full)

        sync_part = compute_partial_hash(t_file)
        async_part = asyncio.run(compute_partial_hash_async(t_file))
        self.assertEqual(sync_part, async_part)

        # Ejecución directa del motor asíncrono scan_directory_async
        dups, summary = asyncio.run(scan_directory_async(async_dir))
        self.assertEqual(summary.total_files_scanned, 1)


if __name__ == "__main__":
    unittest.main()
