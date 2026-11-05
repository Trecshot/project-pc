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
    purge_quarantine_session,
    purge_all_quarantine_sessions,
    delete_redundant_files,
    execute_deletion_plan,
    QuarantineResult,
    RestoreResult,
    DeleteResult
)
from datacleaner.reporter import (
    build_audit_plan,
    generate_report_dict,
    print_rich_report,
    export_report_json,
    format_bytes
)
from datacleaner.history import (
    CleaningHistoryManager,
    HistoryEntry,
    HistorySummary,
    format_bytes_auto,
    format_bytes_with_equivalence
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
    "purge_quarantine_session",
    "purge_all_quarantine_sessions",
    "delete_redundant_files",
    "execute_deletion_plan",
    "QuarantineResult",
    "RestoreResult",
    "DeleteResult",
    "build_audit_plan",
    "generate_report_dict",
    "print_rich_report",
    "export_report_json",
    "format_bytes",
    "CleaningHistoryManager",
    "HistoryEntry",
    "HistorySummary",
    "format_bytes_auto",
    "format_bytes_with_equivalence"
]
