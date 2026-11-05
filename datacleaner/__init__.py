"""
DataCleaner - Gestor Local de Organización y Auditoría de Archivos por Hash
"""

from datacleaner.security import validate_target_path, SYSTEM_BLACKLIST
from datacleaner.hasher import (
    compute_file_hash,
    compute_partial_hash,
    compute_file_hash_async,
    compute_partial_hash_async,
)
from datacleaner.bloom import BloomFilter
from datacleaner.magic import analyze_file_signature, FileSignatureReport
from datacleaner.scanner import (
    scan_directory_for_duplicates,
    scan_directory_async,
    ScanSummary,
)
from datacleaner.rules import select_file_to_keep, KeepRule
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
    HardlinkResult
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
from datacleaner.scheduler import (
    build_schtasks_create_command,
    register_scheduled_scan,
    query_scheduled_scan,
    remove_scheduled_scan,
    ScheduledTaskResult,
)

__version__ = "1.0.0"
__all__ = [
    "validate_target_path",
    "SYSTEM_BLACKLIST",
    "compute_file_hash",
    "compute_partial_hash",
    "compute_file_hash_async",
    "compute_partial_hash_async",
    "BloomFilter",
    "analyze_file_signature",
    "FileSignatureReport",
    "scan_directory_for_duplicates",
    "scan_directory_async",
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
    "deduplicate_with_hardlinks",
    "QuarantineResult",
    "RestoreResult",
    "DeleteResult",
    "HardlinkResult",
    "build_audit_plan",
    "generate_report_dict",
    "print_rich_report",
    "export_report_json",
    "format_bytes",
    "CleaningHistoryManager",
    "HistoryEntry",
    "HistorySummary",
    "format_bytes_auto",
    "format_bytes_with_equivalence",
    "build_schtasks_create_command",
    "register_scheduled_scan",
    "query_scheduled_scan",
    "remove_scheduled_scan",
    "ScheduledTaskResult",
]
