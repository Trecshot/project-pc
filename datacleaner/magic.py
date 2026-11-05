"""
Módulo de Análisis de Integridad por Firmas Binarias (Magic Numbers / Forense)
DataCleaner CLI/GUI

Inspecciona los primeros 4 a 16 bytes de cada archivo evaluado para determinar
de forma determinista su tipo MIME real mediante firmas hexadecimales (Magic Numbers),
detectando extensiones manipuladas/ofuscadas y ejecutables camuflados como documentos.
"""

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass
class FileSignatureReport:
    """Resultado forense de validación de cabecera binaria (Magic Number)."""
    file_path: str
    declared_extension: str
    header_hex: str
    detected_mime: str
    detected_format: str
    integrity_status: str  # "VERIFIED", "EXTENSION_MISMATCH", "THREAT_EXECUTABLE_CAMOUFLAGED", "TEXT_OR_GENERIC", "EMPTY_OR_UNREADABLE"
    is_anomaly: bool
    forensic_note: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Tabla determinista de firmas binarias (Magic Numbers)
# Tupla: (offset, magic_bytes, mime_type, format_label, valid_extensions, is_executable)
MAGIC_SIGNATURES: list[tuple[int, bytes, str, str, set[str], bool]] = [
    # Documentos y Bases de Datos
    (0, b"%PDF", "application/pdf", "PDF Document (%PDF)", {".pdf", ".ai"}, False),
    (0, b"SQLite format 3\x00", "application/vnd.sqlite3", "SQLite 3 Database", {".db", ".sqlite", ".sqlite3", ".db3"}, False),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage", "MS Office Legacy (OLE2)", {".doc", ".xls", ".ppt", ".msi", ".msg"}, False),

    # Ejecutables y Binarios de Sistema (Críticos para detección de camuflaje)
    (0, b"MZ", "application/x-msdownload", "Windows PE Executable (MZ)", {".exe", ".dll", ".sys", ".scr", ".ocx", ".pyd", ".cpl", ".efi", ".com"}, True),
    (0, b"\x7fELF", "application/x-elf", "Linux/Unix ELF Binary", {".elf", ".so", ".bin", ".out", ".o", ""}, True),
    (0, b"\xfe\xed\xfa\xce", "application/x-mach-binary", "macOS Mach-O 32-bit", {".dylib", ".bundle", ".so", ""}, True),
    (0, b"\xfe\xed\xfa\xcf", "application/x-mach-binary", "macOS Mach-O 64-bit", {".dylib", ".bundle", ".so", ""}, True),

    # Imágenes
    (0, b"\x89PNG\r\n\x1a\n", "image/png", "PNG Image", {".png", ".apng"}, False),
    (0, b"\xff\xd8\xff", "image/jpeg", "JPEG Image", {".jpg", ".jpeg", ".jfif", ".jpe"}, False),
    (0, b"GIF87a", "image/gif", "GIF Image (87a)", {".gif"}, False),
    (0, b"GIF89a", "image/gif", "GIF Image (89a)", {".gif"}, False),
    (0, b"BM", "image/bmp", "Bitmap Image (BMP)", {".bmp", ".dib"}, False),
    (0, b"\x00\x00\x01\x00", "image/x-icon", "Windows Icon (ICO)", {".ico"}, False),

    # Contenedores Comprimidos y Paquetes OOXML
    (0, b"PK\x03\x04", "application/zip", "ZIP / OOXML Archive", {
        ".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".ipa",
        ".odt", ".ods", ".odp", ".epub", ".whl", ".nupkg", ".vsix", ".kmz"
    }, False),
    (0, b"PK\x05\x06", "application/zip", "ZIP Empty Archive", {".zip", ".docx", ".xlsx", ".pptx", ".jar"}, False),
    (0, b"Rar!\x1a\x07", "application/x-rar-compressed", "RAR Archive", {".rar", ".cbr"}, False),
    (0, b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7-Zip Archive", {".7z", ".cb7"}, False),
    (0, b"\x1f\x8b", "application/gzip", "GZIP Compressed", {".gz", ".tgz", ".svgz"}, False),
    (0, b"BZh", "application/x-bzip2", "BZIP2 Compressed", {".bz2", ".tbz2"}, False),
    (0, b"\xfd7zXZ\x00", "application/x-xz", "XZ Compressed", {".xz", ".txz"}, False),

    # Audio y Video
    (0, b"ID3", "audio/mpeg", "MP3 Audio (ID3v2)", {".mp3", ".mpga"}, False),
    (0, b"\xff\xfb", "audio/mpeg", "MP3 Audio Frame", {".mp3", ".mpga"}, False),
    (0, b"OggS", "application/ogg", "OGG Multimedia", {".ogg", ".oga", ".ogv", ".opus"}, False),
    (0, b"fLaC", "audio/flac", "FLAC Audio", {".flac"}, False),
    (4, b"ftyp", "video/mp4", "ISO Media / MP4 Container", {".mp4", ".m4a", ".m4v", ".mov", ".3gp", ".heic", ".avif"}, False),
    (0, b"RIFF", "application/x-riff", "RIFF Container (WAV/AVI/WEBP)", {".wav", ".avi", ".webp", ".ani", ".cda"}, False),
]

# Extensiones que exigen obligatoriamente una cabecera binaria conocida
STRICT_BINARY_EXTENSIONS: dict[str, tuple[str, str]] = {
    ".pdf": ("application/pdf", "25 50 44 46 (%PDF)"),
    ".png": ("image/png", "89 50 4E 47 (PNG)"),
    ".jpg": ("image/jpeg", "FF D8 FF (JPEG)"),
    ".jpeg": ("image/jpeg", "FF D8 FF (JPEG)"),
    ".gif": ("image/gif", "47 49 46 38 (GIF)"),
    ".zip": ("application/zip", "50 4B 03 04 (PK)"),
    ".rar": ("application/x-rar-compressed", "52 61 72 21 (Rar!)"),
    ".7z": ("application/x-7z-compressed", "37 7A BC AF 27 1C (7z)"),
    ".exe": ("application/x-msdownload", "4D 5A (MZ)"),
    ".dll": ("application/x-msdownload", "4D 5A (MZ)"),
    ".sqlite": ("application/vnd.sqlite3", "SQLite format 3"),
    ".sqlite3": ("application/vnd.sqlite3", "SQLite format 3"),
}

# Extensiones benignas (documentos, imágenes, texto, audio/video) donde un ejecutable camuflado es crítico
DOCUMENT_OR_MEDIA_EXTENSIONS: set[str] = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico",
    ".mp3", ".wav", ".flac", ".ogg", ".mp4", ".avi", ".mkv", ".mov",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".json", ".xml", ".html", ".md"
}


def read_magic_header(file_path: Path, num_bytes: int = 16) -> bytes | None:
    """Lee de forma segura los primeros `num_bytes` bytes de un archivo."""
    try:
        with open(file_path, "rb") as f:
            return f.read(num_bytes)
    except (PermissionError, OSError, FileNotFoundError, IOError):
        return None


def analyze_file_signature(file_path: Path) -> FileSignatureReport:
    """
    Analiza la cabecera binaria (primeros 4 a 16 bytes) del archivo y verifica su
    coherencia frente a la extensión declarada.
    """
    ext = file_path.suffix.lower()
    header = read_magic_header(file_path, 16)

    if header is None or len(header) == 0:
        return FileSignatureReport(
            file_path=str(file_path),
            declared_extension=ext or "(sin ext)",
            header_hex="" if header is None else "EMPTY",
            detected_mime="application/x-empty",
            detected_format="Archivo vacío o inaccesible",
            integrity_status="EMPTY_OR_UNREADABLE",
            is_anomaly=False,
            forensic_note="Sin bytes de cabecera para evaluar."
        )

    header_hex = " ".join(f"{b:02X}" for b in header[:8])

    # Buscar coincidencia en la tabla de Magic Numbers
    matched_sig = None
    for offset, magic_bytes, mime_type, fmt_label, valid_exts, is_exec in MAGIC_SIGNATURES:
        if len(header) >= offset + len(magic_bytes):
            if header[offset:offset + len(magic_bytes)] == magic_bytes:
                matched_sig = (mime_type, fmt_label, valid_exts, is_exec)
                break

    if matched_sig is not None:
        mime_type, fmt_label, valid_exts, is_exec = matched_sig

        # Caso 1: Ejecutable binario camuflado como documento/imagen/multimedia
        if is_exec and ext in DOCUMENT_OR_MEDIA_EXTENSIONS:
            return FileSignatureReport(
                file_path=str(file_path),
                declared_extension=ext,
                header_hex=header_hex,
                detected_mime=mime_type,
                detected_format=fmt_label,
                integrity_status="THREAT_EXECUTABLE_CAMOUFLAGED",
                is_anomaly=True,
                forensic_note=(
                    f"ALERTA FORENSE: Ejecutable '{fmt_label}' ({header_hex}) "
                    f"camuflado con extensión '{ext}'."
                )
            )

        # Caso 2: La firma binaria real no corresponde con la extensión declarada
        if ext and ext not in valid_exts:
            return FileSignatureReport(
                file_path=str(file_path),
                declared_extension=ext,
                header_hex=header_hex,
                detected_mime=mime_type,
                detected_format=fmt_label,
                integrity_status="EXTENSION_MISMATCH",
                is_anomaly=True,
                forensic_note=(
                    f"Extensión ofuscada/manipulada: declara '{ext}' pero su firma binaria "
                    f"es '{fmt_label}' ({mime_type}, {header_hex})."
                )
            )

        # Caso 3: Firma binaria verificada y consistente con la extensión
        return FileSignatureReport(
            file_path=str(file_path),
            declared_extension=ext or "(sin ext)",
            header_hex=header_hex,
            detected_mime=mime_type,
            detected_format=fmt_label,
            integrity_status="VERIFIED",
            is_anomaly=False,
            forensic_note=f"Firma íntegra verificada: {fmt_label} ({mime_type})."
        )

    # Si no coincidió con ninguna firma conocida, pero su extensión exige una firma estricta (ej. .pdf, .png, .jpg, .exe)
    if ext in STRICT_BINARY_EXTENSIONS:
        expected_mime, expected_magic = STRICT_BINARY_EXTENSIONS[ext]
        return FileSignatureReport(
            file_path=str(file_path),
            declared_extension=ext,
            header_hex=header_hex,
            detected_mime="application/octet-stream",
            detected_format="Cabecera desconocida / Corrupta",
            integrity_status="EXTENSION_MISMATCH",
            is_anomaly=True,
            forensic_note=(
                f"Inconsistencia binaria: el archivo '{ext}' debería iniciar con "
                f"{expected_magic}, pero presenta cabecera [{header_hex}]."
            )
        )

    # Heurística rápida para distinguir texto plano (UTF-8 / ASCII) de binario genérico
    is_likely_text = all(b in (9, 10, 13) or (32 <= b <= 126) or b >= 128 for b in header)
    detected_mime = "text/plain" if is_likely_text else "application/octet-stream"
    detected_fmt = "Texto plano / Script" if is_likely_text else "Datos binarios genéricos"

    return FileSignatureReport(
        file_path=str(file_path),
        declared_extension=ext or "(sin ext)",
        header_hex=header_hex,
        detected_mime=detected_mime,
        detected_format=detected_fmt,
        integrity_status="TEXT_OR_GENERIC",
        is_anomaly=False,
        forensic_note=f"Formato genérico ({detected_mime})."
    )
