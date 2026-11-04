"""
DataCleaner - Gestor Local de Organización y Auditoría de Archivos por Hash
"""

from datacleaner.security import validate_target_path, SYSTEM_BLACKLIST
from datacleaner.hasher import compute_file_hash
from datacleaner.scanner import scan_directory_for_duplicates, ScanSummary
from datacleaner.rules import select_file_to_keep, KeepRule
from datacleaner.quarantine import (
    quarantine_redundant_files,
    restore_from_quarantine,
    find_quarantine_sessions,
    QuarantineResult,
    RestoreResult
)
from datacleaner.reporter import (
    build_audit_plan,
    generate_report_dict,
    print_rich_report,
    export_report_json,
    format_bytes
)

__version__ = "1.0.0"
__all__ = [
    "validate_target_path",
    "SYSTEM_BLACKLIST",
    "compute_file_hash",
    "scan_directory_for_duplicates",
    "ScanSummary",
    "select_file_to_keep",
    "KeepRule",
    "quarantine_redundant_files",
    "restore_from_quarantine",
    "find_quarantine_sessions",
    "QuarantineResult",
    "RestoreResult",
    "build_audit_plan",
    "generate_report_dict",
    "print_rich_report",
    "export_report_json",
    "format_bytes"
]
