"""
Interfaz de Línea de Comandos (CLI) con Rich
DataCleaner CLI

Permite escanear, auditar (dry-run), aislar en cuarentena (soft-delete) y restaurar archivos
mediante una experiencia enriquecida con Rich (colores, tablas, barras de progreso).
"""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Confirm

from datacleaner.security import validate_target_path
from datacleaner.scanner import scan_directory_for_duplicates
from datacleaner.rules import KeepRule
from datacleaner.quarantine import (
    quarantine_redundant_files,
    restore_from_quarantine,
    find_quarantine_sessions,
    purge_quarantine_session,
    purge_all_quarantine_sessions,
    execute_deletion_plan,
    DeleteResult
)
from datacleaner.reporter import (
    build_audit_plan,
    generate_report_dict,
    print_rich_report,
    export_report_json,
    format_bytes
)
from datacleaner.history import CleaningHistoryManager

console = Console()

def cmd_scan(args: argparse.Namespace):
    """Ejecuta la auditoría en modo simulación (Dry-Run)."""
    try:
        target_dir = validate_target_path(args.path)
    except Exception as e:
        console.print(f"[bold red]Error de validación de seguridad:[/bold red] {e}")
        sys.exit(1)

    console.print(f"\n[cyan]Iniciando escaneo de seguridad en:[/cyan] [bold]{target_dir}[/bold]")
    console.print(f"[dim]Hilos de trabajo (I/O Workers): {args.workers} | Regla: {args.keep_rule}[/dim]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True
    ) as progress:
        task_id = progress.add_task("[cyan]Analizando archivos por tamaño y hash SHA-256...", total=100)

        def on_progress(done: int, total: int, filename: str):
            if total > 0:
                percent = int((done / total) * 100)
                progress.update(
                    task_id,
                    completed=percent,
                    description=f"[cyan]Calculando SHA-256 ({done}/{total}): [dim]{filename[:30]}[/dim]"
                )

        duplicates, summary = scan_directory_for_duplicates(
            base_dir=target_dir,
            max_workers=args.workers,
            progress_callback=on_progress
        )

    # Generar y mostrar el reporte Dry-Run
    report_data = generate_report_dict(
        base_dir=target_dir,
        duplicates=duplicates,
        summary=summary,
        keep_rule=args.keep_rule
    )
    print_rich_report(report_data, console=console)

    # Exportación opcional a JSON
    if args.json_out:
        out_file = export_report_json(report_data, args.json_out)
        console.print(f"[bold green][OK] Reporte exportado a JSON:[/bold green] [underline]{out_file}[/underline]\n")

    # Si hay duplicados y el usuario especificó --quarantine-interactive, ofrecer moverlos
    if report_data["metadata"]["total_redundant_files"] > 0 and args.interactive:
        if Confirm.ask("\n[bold yellow]¿Desea mover los archivos redundantes a cuarentena ahora?[/bold yellow]"):
            _execute_quarantine(target_dir, duplicates, args.keep_rule)

def cmd_quarantine(args: argparse.Namespace):
    """Ejecuta el aislamiento en cuarentena (Soft-Delete) con confirmación explícita."""
    try:
        target_dir = validate_target_path(args.path)
    except Exception as e:
        console.print(f"[bold red]Error de seguridad:[/bold red] {e}")
        sys.exit(1)

    console.print(f"\n[cyan]Escaneando para cuarentena en:[/cyan] [bold]{target_dir}[/bold]...")

    duplicates, summary = scan_directory_for_duplicates(
        base_dir=target_dir,
        max_workers=args.workers
    )

    report_data = generate_report_dict(
        base_dir=target_dir,
        duplicates=duplicates,
        summary=summary,
        keep_rule=args.keep_rule
    )

    print_rich_report(report_data, console=console)

    total_redundant = report_data["metadata"]["total_redundant_files"]
    if total_redundant == 0:
        console.print("[green]No hay archivos redundantes para mover.[/green]")
        return

    # Opción 2 y 3: Eliminación directa (Papelera o Permanente)
    if getattr(args, "direct", False):
        use_trash = getattr(args, "trash", False) or not getattr(args, "permanent", False)
        if getattr(args, "permanent", False):
            use_trash = False

        action_desc = "a la Papelera de Reciclaje" if use_trash else "definitivamente del disco (IRREVERSIBLE)"
        if not args.yes:
            confirm = Confirm.ask(
                f"[bold yellow]¿Confirmar eliminación {action_desc} de {total_redundant} archivos?[/bold yellow]",
                default=False
            )
            if not confirm:
                console.print("[dim]Operación cancelada por el usuario.[/dim]")
                return

        plan = build_audit_plan(duplicates, keep_rule=args.keep_rule, base_dir=target_dir)
        del_res = execute_deletion_plan(plan, use_trash=use_trash)
        if del_res.total_deleted > 0:
            try:
                CleaningHistoryManager().record_event(
                    action_type="TRASH" if del_res.used_trash else "PERMANENT",
                    target_dir=str(target_dir),
                    files_count=del_res.total_deleted,
                    bytes_affected=del_res.total_bytes_deleted,
                    details="CLI: Papelera de Reciclaje" if del_res.used_trash else "CLI: Eliminación permanente"
                )
            except Exception:
                pass

        console.print(f"\n[bold green][OK] Eliminación directa finalizada.[/bold green]")
        console.print(f"  * Archivos eliminados: [bold]{del_res.total_deleted}[/bold] ({format_bytes(del_res.total_bytes_deleted)})")
        console.print(f"  * Modo: {'Papelera de Reciclaje (send2trash)' if del_res.used_trash else 'Permanente (unlink)'}")
        if del_res.errors:
            for err in del_res.errors:
                console.print(f"  - [red]{err}[/red]")
        return

    # Principio 1.2: Ninguna operación destructiva/modificatoria sin aprobación
    if not args.yes:
        confirm = Confirm.ask(
            f"[bold yellow]¿Confirmar traslado de {total_redundant} archivos "
            f"({report_data['metadata']['recoverable_formatted']}) a Cuarentena?[/bold yellow]",
            default=False
        )
        if not confirm:
            console.print("[dim]Operación cancelada por el usuario. No se modificó ningún archivo.[/dim]")
            return

    _execute_quarantine(target_dir, duplicates, args.keep_rule, custom_dir=args.quarantine_dir)

def _execute_quarantine(base_dir: Path, duplicates: dict, keep_rule: str, custom_dir: str | None = None):
    """Función auxiliar para trasladar a cuarentena y presentar resultado."""
    custom_p = Path(custom_dir) if custom_dir else None
    plan = build_audit_plan(duplicates, keep_rule=keep_rule, base_dir=base_dir)

    with console.status("[yellow]Trasladando archivos redundantes a directorio de Cuarentena...[/yellow]"):
        result = quarantine_redundant_files(base_dir, plan, custom_quarantine_dir=custom_p)

    if result.total_moved > 0:
        try:
            CleaningHistoryManager().record_event(
                action_type="QUARANTINE",
                target_dir=str(base_dir),
                files_count=result.total_moved,
                bytes_affected=result.total_bytes_moved,
                details=f"CLI: Sesión {result.session_id}"
            )
        except Exception:
            pass

    console.print()
    console.print(f"[bold green][OK] Cuarentena completada con exito.[/bold green]")
    console.print(f"  * Archivos trasladados: [bold]{result.total_moved}[/bold] ({format_bytes(result.total_bytes_moved)})")
    console.print(f"  * Directorio de Cuarentena: [cyan]{result.quarantine_dir}[/cyan]")
    console.print(f"  * Archivo Manifiesto: [yellow]{result.manifest_path}[/yellow]")
    console.print(f"\n[dim]Para restaurar en cualquier momento, ejecute:[/dim]")
    console.print(f"  [bold]datacleaner restore \"{result.manifest_path}\"[/bold]\n")

    if result.errors:
        console.print("[bold red]Advertencias encontradas:[/bold red]")
        for err in result.errors:
            console.print(f"  - {err}")

def cmd_restore(args: argparse.Namespace):
    """Restaura archivos previamente puestos en cuarentena mediante manifest.json."""
    manifest_p = Path(args.manifest)
    if not manifest_p.exists():
        console.print(f"[bold red]Error:[/bold red] No se encuentra el archivo de manifiesto: {manifest_p}")
        sys.exit(1)

    console.print(f"\n[cyan]Iniciando restauración desde manifiesto:[/cyan] [bold]{manifest_p}[/bold]")

    with console.status("[yellow]Restaurando archivos a sus ubicaciones originales...[/yellow]"):
        try:
            res = restore_from_quarantine(manifest_p)
        except Exception as e:
            console.print(f"[bold red]Fallo al procesar restauración:[/bold red] {e}")
            sys.exit(1)

    console.print(f"\n[bold green][OK] Restauracion finalizada.[/bold green]")
    console.print(f"  * Archivos devueltos a su origen: [bold]{res.total_restored}[/bold] ({format_bytes(res.total_bytes_restored)})")
    if res.total_restored > 0:
        try:
            CleaningHistoryManager().record_event(
                action_type="RESTORE",
                target_dir=str(manifest_p.parent),
                files_count=res.total_restored,
                bytes_affected=res.total_bytes_restored,
                details=f"CLI: Restauración desde {manifest_p.name}"
            )
        except Exception:
            pass
    if res.skipped_count:
        console.print(f"  • Archivos omitidos (ya restaurados anteriormente): [dim]{res.skipped_count}[/dim]")

    if res.errors:
        console.print("\n[bold red]Errores o conflictos durante la restauración:[/bold red]")
        for err in res.errors:
            console.print(f"  - [red]{err}[/red]")
    console.print()

def cmd_purge(args: argparse.Namespace):
    """Opción 1: Purga definitivamente las carpetas de cuarentena."""
    try:
        target_dir = validate_target_path(args.path)
    except Exception as e:
        console.print(f"[bold red]Error de validación de seguridad:[/bold red] {e}")
        sys.exit(1)

    sessions = find_quarantine_sessions(target_dir)
    if not sessions:
        console.print(f"[yellow]No se encontraron sesiones de cuarentena (_quarantine_*) en: {target_dir}[/yellow]")
        return

    console.print(f"\n[cyan]Se encontraron {len(sessions)} sesión(es) de cuarentena en:[/cyan] [bold]{target_dir}[/bold]")
    for idx, s in enumerate(sessions, 1):
        console.print(f"  {idx}. [bold]{s['session_id']}[/bold] - {s['total_files']} archivos ({s['total_bytes_formatted']}) [{s['timestamp']}]")

    if not args.yes:
        confirm = Confirm.ask(
            "\n[bold red]¿Confirmar ELIMINACIÓN PERMANENTE (purgar) de estas sesiones de cuarentena?[/bold red]",
            default=False
        )
        if not confirm:
            console.print("[dim]Operación cancelada por el usuario. No se modificó ningún archivo.[/dim]")
            return

    total_purged_files = sum(s.get("total_files", 0) for s in sessions)
    total_purged_bytes = sum(s.get("total_bytes", 0) for s in sessions)
    purged = purge_all_quarantine_sessions(target_dir)
    if purged > 0:
        try:
            CleaningHistoryManager().record_event(
                action_type="PURGE",
                target_dir=str(target_dir),
                files_count=total_purged_files,
                bytes_affected=total_purged_bytes,
                details=f"CLI: Purga de {purged} sesión(es) de cuarentena"
            )
        except Exception:
            pass

    console.print(f"\n[bold green][OK] Se purgaron {purged} sesión(es) de cuarentena definitivamente.[/bold green]\n")

def cmd_gui(args: argparse.Namespace):
    """Abre la interfaz gráfica de usuario de escritorio (GUI)."""
    try:
        from datacleaner.gui import launch_gui
        launch_gui(initial_dir=args.path if hasattr(args, "path") else None)
    except Exception as e:
        console.print(f"[bold red]Error al iniciar la GUI:[/bold red] {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        prog="datacleaner",
        description="DataCleaner: Gestor Local de Organización y Auditoría de Archivos por Hash (SHA-256)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # Comando 'scan' (Dry-Run por defecto)
    scan_parser = subparsers.add_parser("scan", help="Auditar directorio en modo simulación (Dry-Run)")
    scan_parser.add_argument("path", help="Ruta del directorio a auditar")
    scan_parser.add_argument(
        "--keep-rule",
        choices=[r.value for r in KeepRule],
        default=KeepRule.DEEPEST_THEN_NEWEST.value,
        help="Criterio para seleccionar el archivo que se conserva (default: deepest_then_newest)"
    )
    scan_parser.add_argument("--workers", type=int, default=4, help="Número de hilos para cálculo de hashes (default: 4)")
    scan_parser.add_argument("--json-out", help="Ruta de archivo para exportar reporte en JSON")
    scan_parser.add_argument("-i", "--interactive", action="store_true", help="Ofrecer cuarentena interactiva al terminar")
    scan_parser.set_defaults(func=cmd_scan)

    # Comando 'quarantine'
    quar_parser = subparsers.add_parser("quarantine", help="Mover duplicados redundantes a directorio de cuarentena")
    quar_parser.add_argument("path", help="Ruta del directorio a procesar")
    quar_parser.add_argument(
        "--keep-rule",
        choices=[r.value for r in KeepRule],
        default=KeepRule.DEEPEST_THEN_NEWEST.value,
        help="Criterio para seleccionar archivo conservado"
    )
    quar_parser.add_argument("--workers", type=int, default=4, help="Número de hilos de trabajo")
    quar_parser.add_argument("-y", "--yes", action="store_true", help="Omitir confirmación manual interactiva")
    quar_parser.add_argument("--quarantine-dir", help="Directorio destino personalizado para la cuarentena")
    quar_parser.add_argument("--direct", action="store_true", help="Eliminar directamente sin enviar a cuarentena")
    quar_parser.add_argument("--trash", action="store_true", help="Enviar a la Papelera de Windows (al usar --direct)")
    quar_parser.add_argument("--permanent", action="store_true", help="Eliminar permanentemente del disco (al usar --direct)")
    quar_parser.set_defaults(func=cmd_quarantine)

    # Comando 'restore'
    rest_parser = subparsers.add_parser("restore", help="Restaurar archivos desde un archivo manifest.json")
    rest_parser.add_argument("manifest", help="Ruta al archivo manifest.json de la cuarentena")
    rest_parser.set_defaults(func=cmd_restore)

    # Comando 'purge' (Opción 1: Vaciar / Purgar Cuarentenas)
    purge_parser = subparsers.add_parser("purge", help="Vaciar/purgar definitivamente sesiones de cuarentena")
    purge_parser.add_argument("path", help="Ruta del directorio auditado con carpetas de cuarentena")
    purge_parser.add_argument("-y", "--yes", action="store_true", help="Omitir confirmación manual interactiva")
    purge_parser.set_defaults(func=cmd_purge)

    # Comando 'gui'
    gui_parser = subparsers.add_parser("gui", help="Iniciar la Interfaz Gráfica de Usuario (GUI)")
    gui_parser.add_argument("path", nargs="?", help="Directorio inicial opcional para abrir en la GUI")
    gui_parser.set_defaults(func=cmd_gui)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)

if __name__ == "__main__":
    main()
