"""
Generador de Reportes de Auditoría y Previsualización Dry-Run
DataCleaner CLI/GUI

Construye reportes detallados en consola (con tablas Rich) y en formato JSON.
Cumple con RF-05 y el Principio de Simulación Obligatoria (1.2).
"""

from pathlib import Path
from dataclasses import dataclass
from typing import Any
import json
import math

from datacleaner.rules import select_file_to_keep, KeepRule
from datacleaner.scanner import ScanSummary

def format_bytes(bytes_count: int) -> str:
    """Convierte bytes a formato legible (B, KB, MB, GB, TB) escalando automáticamente."""
    if bytes_count <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    val = float(bytes_count)
    idx = 0
    while val >= 1000.0 and idx < len(units) - 1:
        val /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(val)} B"
    return f"{round(val, 2)} {units[idx]}"

def build_audit_plan(
    duplicates: dict[str, list[Path]],
    keep_rule: str = "deepest_then_newest"
) -> list[dict[str, Any]]:
    """
    Construye el plan de auditoría determinando para cada hash qué archivo se conserva
    y cuáles se asignan a cuarentena.
    """
    plan = []
    for sha, paths in duplicates.items():
        kept_file, quarantine_files = select_file_to_keep(paths, rule=keep_rule)
        try:
            size = paths[0].stat().st_size
        except (OSError, IndexError):
            size = 0

        plan.append({
            "hash": sha,
            "size_per_file": size,
            "size_formatted": format_bytes(size),
            "keep": kept_file,
            "quarantine": quarantine_files,
            "recoverable_bytes": size * len(quarantine_files),
            "recoverable_formatted": format_bytes(size * len(quarantine_files)),
            "total_group_files": len(paths)
        })
    return plan

def generate_report_dict(
    base_dir: Path,
    duplicates: dict[str, list[Path]],
    summary: ScanSummary,
    keep_rule: str = "deepest_then_newest"
) -> dict[str, Any]:
    """Genera la estructura de diccionario completa para reporte / exportación JSON."""
    plan = build_audit_plan(duplicates, keep_rule=keep_rule)

    total_quarantine_files = sum(len(item["quarantine"]) for item in plan)
    total_recoverable_bytes = sum(item["recoverable_bytes"] for item in plan)

    return {
        "metadata": {
            "base_directory": str(base_dir.resolve()),
            "keep_rule_applied": keep_rule,
            "total_files_scanned": summary.total_files_scanned,
            "total_bytes_scanned": summary.total_bytes_scanned,
            "total_bytes_scanned_formatted": format_bytes(summary.total_bytes_scanned),
            "duplicate_groups": len(duplicates),
            "total_redundant_files": total_quarantine_files,
            "recoverable_bytes": total_recoverable_bytes,
            "recoverable_formatted": format_bytes(total_recoverable_bytes),
            "unreadable_files": summary.unreadable_files_count,
            "warnings_count": len(summary.warnings),
            "warnings": summary.warnings
        },
        "groups": [
            {
                "hash_sha256": g["hash"],
                "file_size_bytes": g["size_per_file"],
                "file_size_formatted": g["size_formatted"],
                "kept_file": str(g["keep"].resolve()),
                "quarantine_files": [str(p.resolve()) for p in g["quarantine"]],
                "group_recoverable_bytes": g["recoverable_bytes"],
                "group_recoverable_formatted": g["recoverable_formatted"]
            }
            for g in plan
        ]
    }

def print_rich_report(report_data: dict[str, Any], console=None):
    """
    Renderiza el reporte previo (Dry-Run) utilizando la librería Rich en consola.
    """
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
    except ImportError:
        # Fallback si rich no estuviese disponible
        _print_plain_report(report_data)
        return

    console = console or Console()
    meta = report_data["metadata"]
    groups = report_data["groups"]

    console.print()
    # Panel de Encabezado
    header_text = Text()
    header_text.append("REPORTE PREVIO DE AUDITORÍA (DRY-RUN)\n", style="bold cyan")
    header_text.append(f"Directorio Objetivo: {meta['base_directory']}\n", style="white")
    header_text.append(f"Regla de Conservación: {meta['keep_rule_applied']}\n", style="yellow")
    header_text.append(f"Archivos Analizados: {meta['total_files_scanned']:,} ({meta['total_bytes_scanned_formatted']})\n", style="dim")
    header_text.append(f"Grupos Duplicados: {meta['duplicate_groups']} | ", style="magenta")
    header_text.append(f"Copias Redundantes: {meta['total_redundant_files']} | ", style="red")
    header_text.append(f"Espacio Recuperable: {meta['recoverable_formatted']}", style="bold green")

    console.print(Panel(header_text, title="DataCleaner - Auditoría por Hash", border_style="cyan"))

    if not groups:
        console.print("[bold green][OK] No se encontraron archivos duplicados. El almacenamiento está limpio.[/bold green]\n")
        return

    # Tabla de grupos duplicados
    table = Table(title="Detalle de Duplicados Binarios (SHA-256)", show_lines=True)
    table.add_column("Grupo", justify="center", style="dim", width=6)
    table.add_column("Hash SHA-256 (Prefijo)", justify="center", style="cyan", width=16)
    table.add_column("Tamaño", justify="right", style="magenta", width=12)
    table.add_column("Estado", justify="center", width=12)
    table.add_column("Ruta del Archivo", justify="left")

    for idx, g in enumerate(groups, start=1):
        short_hash = g["hash_sha256"][:12] + "..."
        f_size = g["file_size_formatted"]

        # Fila del archivo a conservar
        table.add_row(
            str(idx),
            short_hash,
            f_size,
            "[bold green]KEEP[/bold green]",
            f"[green]{g['kept_file']}[/green]"
        )

        # Filas de los archivos redundantes a mover a cuarentena
        for q_file in g["quarantine_files"]:
            table.add_row(
                "",
                "",
                "",
                "[bold yellow]QUARANTINE[/bold yellow]",
                f"[yellow]{q_file}[/yellow]"
            )

    console.print(table)
    console.print(
        f"\n[bold]Espacio recuperable estimado:[/bold] [bold green]{meta['recoverable_formatted']}[/bold green] "
        f"([cyan]{meta['total_redundant_files']}[/cyan] archivos a cuarentena).\n"
    )

    if meta.get("warnings"):
        console.print(f"[bold yellow]Advertencias del sistema ({len(meta['warnings'])}):[/bold yellow]")
        for w in meta["warnings"][:5]:
            console.print(f"  [dim]- {w}[/dim]")
        if len(meta["warnings"]) > 5:
            console.print(f"  [dim]... y {len(meta['warnings']) - 5} advertencias más.[/dim]")
        console.print()

def _print_plain_report(report_data: dict[str, Any]):
    """Impresión estándar de texto plano sin dependencias externas."""
    meta = report_data["metadata"]
    groups = report_data["groups"]

    print("=" * 70)
    print("REPORTE PREVIO DE AUDITORÍA (DRY-RUN)")
    print(f"Directorio Objetivo : {meta['base_directory']}")
    print(f"Regla de Permanencia: {meta['keep_rule_applied']}")
    print(f"Archivos Analizados : {meta['total_files_scanned']}")
    print(f"Grupos Duplicados   : {meta['duplicate_groups']}")
    print(f"Archivos Redundantes: {meta['total_redundant_files']}")
    print(f"Espacio Recuperable : {meta['recoverable_formatted']}")
    print("=" * 70)

    for idx, g in enumerate(groups, start=1):
        print(f"\n[Grupo #{idx}] SHA-256: {g['hash_sha256'][:16]}... ({g['file_size_formatted']})")
        print(f"  [KEEP]       {g['kept_file']}")
        for q in g["quarantine_files"]:
            print(f"  [QUARANTINE] {q}")
    print()

def export_report_json(report_data: dict[str, Any], output_path: Path | str) -> Path:
    """Exporta el reporte a un archivo JSON formateado."""
    out_p = Path(output_path).resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)
    with open(out_p, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    return out_p
