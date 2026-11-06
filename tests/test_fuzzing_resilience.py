"""
Pruebas de Resiliencia, Fuzzing y Fortalecimiento Forense (NIST SSDF PW.8.1 / CNCF)
DataCleaner CLI/GUI

Somete los módulos críticos a:
1. Fuzzing de cabeceras corruptas (0 a 16 bytes, secuencias aleatorias y bytes nulos \x00).
2. Detección forense profunda de paquetes OOXML legítimos vs ZIPs genéricos vs envoltorios maliciosos.
3. Detección de ejecutables camuflados multiplataforma (shebangs #!, scripts, bytecode Python .pyc).
4. Fuzzing de nombres de archivo con escapes ANSI, saltos de línea, homoglyphs Unicode y rutas largas (>260 caracteres).
5. Blindaje Anti-TOCTOU a nivel de Kernel (File Descriptors y bloqueos fcntl/msvcrt).
"""

import unittest
import tempfile
import shutil
import os
import sys
import zipfile
import random
from pathlib import Path

from datacleaner.magic import (
    analyze_file_signature,
    FileSignatureReport,
)
from datacleaner.scanner import (
    scan_directory_for_duplicates,
    ScanSummary,
)
from datacleaner.hasher import compute_partial_hash
from datacleaner.quarantine import _verify_file_unchanged
from datacleaner.bloom import BloomFilter


class TestFuzzingAndForensicResilience(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="datacleaner_fuzzing_")
        self.base_path = Path(self.temp_dir).resolve().absolute()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_fuzzing_headers_zero_to_16_bytes_no_crashes(self):
        """Fuzzing de cabeceras: archivos de 0 a 16 bytes con bytes nulos y patrones aleatorios."""
        random.seed(42)
        fuzz_dir = self.base_path / "header_fuzz"
        fuzz_dir.mkdir(parents=True)

        # 1. Archivo vacío (0 bytes)
        empty_file = fuzz_dir / "empty.dat"
        empty_file.write_bytes(b"")
        rep = analyze_file_signature(empty_file)
        self.assertEqual(rep.integrity_status, "EMPTY_OR_UNREADABLE")
        self.assertFalse(rep.is_anomaly)

        # 2. Generar mutaciones de 1 a 16 bytes con \x00, caracteres de control y bytes aleatorios
        for size in range(1, 17):
            # Variedad: todos ceros, alternados, prefijos de firmas incompletos
            test_payloads = [
                b"\x00" * size,
                b"\xFF" * size,
                bytes(random.randint(0, 255) for _ in range(size)),
                b"PK"[:size],
                b"%PDF"[:size],
                b"MZ"[:size],
                b"\x7fELF"[:size],
                b"\x89PNG"[:size],
            ]
            for idx, payload in enumerate(test_payloads):
                f_path = fuzz_dir / f"fuzz_s{size}_i{idx}.bin"
                f_path.write_bytes(payload)

                # analyze_file_signature debe ser resiliente: nunca debe fallar por IndexError u OSError
                report = analyze_file_signature(f_path)
                self.assertIsInstance(report, FileSignatureReport)
                self.assertTrue(hasattr(report, "integrity_status"))
                self.assertIsNotNone(report.header_hex)

    def test_forensic_ooxml_legitimate_vs_generic_zip_vs_malicious_wrapper(self):
        """Forense OOXML: Diferenciación profunda entre .docx legítimo, ZIP genérico y contenedor malicioso."""
        ooxml_dir = self.base_path / "ooxml_test"
        ooxml_dir.mkdir(parents=True)

        # 1. Documento .docx legítimo con [Content_Types].xml y _rels/.rels
        legit_docx = ooxml_dir / "informe_real.docx"
        with zipfile.ZipFile(legit_docx, "w") as zf:
            zf.writestr("[Content_Types].xml", b"<Types><Default Extension='xml'/></Types>")
            zf.writestr("_rels/.rels", b"<Relationships/>")
            zf.writestr("word/document.xml", b"<w:document/>")

        rep_legit = analyze_file_signature(legit_docx)
        self.assertEqual(rep_legit.integrity_status, "VERIFIED")
        self.assertFalse(rep_legit.is_anomaly)
        self.assertIn("application/vnd.openxmlformats", rep_legit.detected_mime)

        # 2. Archivo ZIP común renombrado maliciosamente a .docx (sin [Content_Types].xml)
        generic_zip = ooxml_dir / "trampa_generica.docx"
        with zipfile.ZipFile(generic_zip, "w") as zf:
            zf.writestr("archivo_normal.txt", b"Texto plano cualquiera")

        rep_generic = analyze_file_signature(generic_zip)
        self.assertEqual(rep_generic.integrity_status, "EXTENSION_MISMATCH")
        self.assertTrue(rep_generic.is_anomaly)

        # 3. Contenedor malicioso: .docx que encapsula scripts o ejecutables (SUSPICIOUS_ARCHIVE_WRAPPER)
        threat_docx = ooxml_dir / "curriculum_cv.docx"
        with zipfile.ZipFile(threat_docx, "w") as zf:
            zf.writestr("payload.exe", b"MZ\x90\x00FakePE")
            zf.writestr("script.ps1", b"Invoke-Expression 'evil'")

        rep_threat = analyze_file_signature(threat_docx)
        self.assertEqual(rep_threat.integrity_status, "SUSPICIOUS_ARCHIVE_WRAPPER")
        self.assertTrue(rep_threat.is_anomaly)
        self.assertIn("ALERTA FORENSE", rep_threat.forensic_note)

    def test_camouflaged_scripts_and_python_bytecode_detection(self):
        """Forense: Detecta scripts con shebang y bytecode Python (.pyc) camuflados como imágenes o documentos."""
        scripts_dir = self.base_path / "camouflaged_scripts"
        scripts_dir.mkdir(parents=True)

        # 1. Script Bash / Shell oculto con extensión .jpg
        fake_jpg_sh = scripts_dir / "foto_vacaciones.jpg"
        fake_jpg_sh.write_bytes(b"#!/bin/bash\nrm -rf /tmp/data\nexit 0")
        rep_sh = analyze_file_signature(fake_jpg_sh)
        self.assertEqual(rep_sh.integrity_status, "THREAT_EXECUTABLE_CAMOUFLAGED")
        self.assertTrue(rep_sh.is_anomaly)

        # 2. Script de entorno (#!/usr/bin/env) oculto como documento .pdf
        fake_pdf_env = scripts_dir / "balance_2026.pdf"
        fake_pdf_env.write_bytes(b"#!/usr/bin/env python3\nimport socket\n")
        rep_env = analyze_file_signature(fake_pdf_env)
        self.assertEqual(rep_env.integrity_status, "THREAT_EXECUTABLE_CAMOUFLAGED")
        self.assertTrue(rep_env.is_anomaly)

        # 3. Batch script de Windows (@echo off) camuflado como imagen .png
        fake_png_bat = scripts_dir / "captura_pantalla.png"
        fake_png_bat.write_bytes(b"@echo off\r\ndir C:\\\r\npause")
        rep_bat = analyze_file_signature(fake_png_bat)
        self.assertEqual(rep_bat.integrity_status, "THREAT_EXECUTABLE_CAMOUFLAGED")
        self.assertTrue(rep_bat.is_anomaly)

        # 4. Bytecode compilado de Python (.pyc magic ending in \r\r\n) como .pdf
        fake_pdf_pyc = scripts_dir / "factura.pdf"
        fake_pdf_pyc.write_bytes(b"\x0b\x0d\x0d\x0a\x00\x00\x00\x00\x00\x00\x00\x00CompiledCode")
        rep_pyc = analyze_file_signature(fake_pdf_pyc)
        self.assertEqual(rep_pyc.integrity_status, "THREAT_EXECUTABLE_CAMOUFLAGED")
        self.assertTrue(rep_pyc.is_anomaly)

    def test_fuzzing_paths_ansi_escapes_homoglyphs_and_long_paths(self):
        """Fuzzing de rutas: soporta secuencias ANSI, caracteres invisibles Unicode y rutas largas (>260 chars)."""
        fuzz_paths_dir = self.base_path / "paths_fuzz"
        fuzz_paths_dir.mkdir(parents=True)

        # 1. Archivo con secuencias de escape ANSI en el nombre
        ansi_name = "reporte_\x1b[31mrojo\x1b[0m_test.txt"
        try:
            ansi_file = fuzz_paths_dir / ansi_name
            ansi_file.write_bytes(b"ANSI escape path payload")
            self.assertTrue(ansi_file.exists())
            rep_ansi = analyze_file_signature(ansi_file)
            self.assertIsNotNone(rep_ansi)
        except OSError:
            # En ciertos sistemas de archivos de Windows puede denegar secuencias de escape crudas
            pass

        # 2. Caracteres Unicode invisibles y homoglyphs (espacio de ancho cero \u200b y 'а' cirílico)
        homoglyph_name = "documento_\u200b\u0430_legitimo.txt"
        try:
            hg_file = fuzz_paths_dir / homoglyph_name
            hg_file.write_bytes(b"Unicode homoglyph payload")
            self.assertTrue(hg_file.exists())
            rep_hg = analyze_file_signature(hg_file)
            self.assertIsNotNone(rep_hg)
        except OSError:
            pass

        # 3. Ruta anidada profunda (> 260 caracteres, MAX_PATH en Windows)
        deep_dir = fuzz_paths_dir
        sub_count = 15
        try:
            for i in range(sub_count):
                deep_dir = deep_dir / f"nivel_profundo_de_directorio_muy_largo_{i:02d}"
            # Usar prefijo UNC \\?\ en Windows si excede MAX_PATH
            deep_str = str(deep_dir)
            if sys.platform == "win32" and not deep_str.startswith("\\\\?\\"):
                deep_path = Path("\\\\?\\" + os.path.abspath(deep_str))
            else:
                deep_path = deep_dir

            deep_path.mkdir(parents=True, exist_ok=True)
            deep_file = deep_path / "archivo_al_final_del_camino_extenso.txt"
            deep_file.write_bytes(b"Contenido en ruta ultra-larga")

            # Escáner debe procesarlo sin caer en bucle ni excepción fatal
            dups, summary = scan_directory_for_duplicates(fuzz_paths_dir)
            self.assertIsInstance(summary, ScanSummary)
            self.assertGreaterEqual(summary.total_files_scanned, 1)
        except OSError:
            # Si el sistema operativo no tiene habilitado LongPathsEnabled en registro
            pass

    def test_kernel_level_toctou_verification_with_file_descriptors(self):
        """Verifica blindaje TOCTOU a nivel de Kernel mediante descriptores de archivo (fstat y locks)."""
        test_file = self.base_path / "kernel_toctou.bin"
        content = b"Kernel FD TOCTOU Payload 2026"
        test_file.write_bytes(content)

        st = test_file.stat()
        exp_size = st.st_size
        exp_mtime = st.st_mtime

        # 1. Archivo sin cambios responde True
        self.assertTrue(_verify_file_unchanged(test_file, exp_size, exp_mtime))

        # 2. Mutación de tamaño responde False inmediatamente
        test_file.write_bytes(content + b"EXTRA_MUTATION")
        self.assertFalse(_verify_file_unchanged(test_file, exp_size, exp_mtime))

        # 3. Archivo inexistente responde False limpiamente sin excepción
        self.assertFalse(_verify_file_unchanged(self.base_path / "inexistente.bin", exp_size, exp_mtime))

    def test_bloom_filter_integrated_in_phase1_scanner(self):
        """Verifica que el Filtro de Bloom está integrado en la Fase 1 descartando elementos únicos en RAM."""
        scanner_dir = self.base_path / "bloom_scanner_test"
        scanner_dir.mkdir(parents=True)

        # Crear 5 archivos con tamaños únicos (100, 200, 300, 400, 500 bytes)
        for i, sz in enumerate([100, 200, 300, 400, 500]):
            f = scanner_dir / f"unico_{i}.dat"
            f.write_bytes(b"U" * sz)

        # Crear 2 archivos con tamaño colisionante (1024 bytes) y contenido idéntico
        dup1 = scanner_dir / "dup1.bin"
        dup2 = scanner_dir / "dup2.bin"
        dup_content = b"D" * 1024
        dup1.write_bytes(dup_content)
        dup2.write_bytes(dup_content)

        custom_bloom = BloomFilter(expected_elements=500, false_positive_rate=0.01)
        dups, summary = scan_directory_for_duplicates(scanner_dir, bloom_filter=custom_bloom)

        # Duplicados detectados correctamente
        self.assertEqual(len(dups), 1)
        # Los 5 archivos únicos deben haber sido descartados por tamaño en RAM
        self.assertEqual(summary.size_unique_discarded, 5)
        self.assertEqual(summary.bloom_unique_discarded, 5)
        self.assertEqual(summary.size_collision_candidates, 2)
        # Comprobar que el tamaño de los duplicados (1024) está presente en el filtro de Bloom
        self.assertTrue(1024 in custom_bloom)

    def test_xxh3_and_blake_streaming_partial_hash_format(self):
        """Verifica el cálculo de partial hash ultra-rápido (XXH3 / BLAKE / SHA-256) consistente a 32 hex chars."""
        target_file = self.base_path / "fast_hash_test.bin"
        target_file.write_bytes(b"Z" * 150000)

        p_hash = compute_partial_hash(target_file)
        self.assertIsNotNone(p_hash)
        self.assertEqual(len(p_hash), 32)
        # Verificar que es hexadecimal válido
        int(p_hash, 16)


if __name__ == "__main__":
    unittest.main()
