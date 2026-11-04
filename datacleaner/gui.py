"""
Interfaz Gráfica de Usuario de Escritorio (Desktop GUI)
DataCleaner GUI

Desarrollada con Tkinter y ttk estándar de Python.
Permite selección de carpetas, validación contra lista negra, escaneo no bloqueante
en segundo plano, previsualización en tabla Treeview, ejecución de cuarentena y restauración reversible.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
from pathlib import Path
from typing import Any

from datacleaner.security import validate_target_path
from datacleaner.scanner import scan_directory_for_duplicates, ScanSummary
from datacleaner.rules import KeepRule
from datacleaner.quarantine import (
    quarantine_redundant_files,
    restore_from_quarantine,
    QuarantineResult,
    RestoreResult
)
from datacleaner.reporter import (
    build_audit_plan,
    generate_report_dict,
    format_bytes,
    export_report_json
)

RULE_OPTIONS = {
    "Ruta más profunda y limpia, luego más reciente (Recomendado)": KeepRule.DEEPEST_THEN_NEWEST.value,
    "Ruta más profunda y limpia, luego más antigua": KeepRule.DEEPEST_THEN_OLDEST.value,
    "Ruta más superficial, luego más reciente": KeepRule.SHALLOWEST_THEN_NEWEST.value,
    "Solo el más reciente": KeepRule.NEWEST_ONLY.value,
    "Solo el más antiguo": KeepRule.OLDEST_ONLY.value,
}

class DataCleanerGUI:
    def __init__(self, root: tk.Tk, initial_dir: str | None = None):
        self.root = root
        self.root.title("DataCleaner - Auditoría y Organización de Archivos por Hash")
        self.root.geometry("1024x720")
        self.root.minsize(800, 560)

        # Estado interno
        self.current_base_dir: Path | None = None
        self.last_duplicates: dict[str, list[Path]] = {}
        self.last_summary: ScanSummary | None = None
        self.last_report: dict[str, Any] | None = None
        self.is_processing = False

        self._apply_styles()
        self._build_ui()

        if initial_dir:
            self.path_entry.insert(0, str(initial_dir))
            self._validate_and_update_path(str(initial_dir))

    def _apply_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), foreground="#1a365d")
        style.configure("SubHeader.TLabel", font=("Segoe UI", 9), foreground="#4a5568")
        style.configure("CardTitle.TLabel", font=("Segoe UI", 9, "bold"), foreground="#718096")
        style.configure("CardValue.TLabel", font=("Segoe UI", 12, "bold"), foreground="#2b6cb0")
        style.configure("Action.TButton", font=("Segoe UI", 9, "bold"))
        style.configure("Quarantine.TButton", font=("Segoe UI", 9, "bold"), foreground="#c53030")

    def _build_ui(self):
        # Contenedor principal
        main_frame = ttk.Frame(self.root, padding=12)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. Cabecera
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            header_frame,
            text="DataCleaner: Auditoría Binaria y Limpieza por Hash SHA-256",
            style="Header.TLabel"
        ).pack(anchor="w")

        ttk.Label(
            header_frame,
            text="Simulación obligatoria (Dry-Run), aislamiento de rutas críticas y cuarentena no destructiva (Soft-Delete).",
            style="SubHeader.TLabel"
        ).pack(anchor="w")

        # 2. Selección de directorio objetivo y configuración
        config_frame = ttk.LabelFrame(main_frame, text=" 1. Selección y Configuración de Auditoría ", padding=10)
        config_frame.pack(fill=tk.X, pady=(0, 8))

        row1 = ttk.Frame(config_frame)
        row1.pack(fill=tk.X, pady=2)

        ttk.Label(row1, text="Directorio Objetivo:").pack(side=tk.LEFT, padx=(0, 6))
        self.path_entry = ttk.Entry(row1)
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

        browse_btn = ttk.Button(row1, text="Examinar...", command=self._browse_directory)
        browse_btn.pack(side=tk.LEFT, padx=4)

        row2 = ttk.Frame(config_frame)
        row2.pack(fill=tk.X, pady=(6, 2))

        ttk.Label(row2, text="Criterio de Permanencia:").pack(side=tk.LEFT, padx=(0, 6))
        self.rule_combobox = ttk.Combobox(
            row2,
            values=list(RULE_OPTIONS.keys()),
            state="readonly",
            width=50
        )
        self.rule_combobox.current(0)
        self.rule_combobox.pack(side=tk.LEFT, padx=4)

        ttk.Label(row2, text="Hilos I/O:").pack(side=tk.LEFT, padx=(12, 4))
        self.workers_spinbox = ttk.Spinbox(row2, from_=1, to=16, width=4)
        self.workers_spinbox.set(4)
        self.workers_spinbox.pack(side=tk.LEFT, padx=4)

        # 3. Barra de Acciones
        action_bar = ttk.Frame(main_frame)
        action_bar.pack(fill=tk.X, pady=(0, 8))

        self.scan_btn = ttk.Button(
            action_bar,
            text="🔍 Iniciar Simulación (Dry-Run)",
            style="Action.TButton",
            command=self._start_scan_thread
        )
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.quarantine_btn = ttk.Button(
            action_bar,
            text="📦 Enviar a Cuarentena",
            style="Quarantine.TButton",
            state=tk.DISABLED,
            command=self._execute_quarantine
        )
        self.quarantine_btn.pack(side=tk.LEFT, padx=6)

        self.restore_btn = ttk.Button(
            action_bar,
            text="🔄 Restaurar desde Cuarentena",
            command=self._restore_from_manifest
        )
        self.restore_btn.pack(side=tk.LEFT, padx=6)

        self.export_btn = ttk.Button(
            action_bar,
            text="💾 Exportar JSON",
            state=tk.DISABLED,
            command=self._export_json_report
        )
        self.export_btn.pack(side=tk.RIGHT, padx=4)

        # 4. Tarjetas de Métricas (Dashboard)
        metrics_frame = ttk.Frame(main_frame)
        metrics_frame.pack(fill=tk.X, pady=(0, 8))

        self.card_files = self._create_card(metrics_frame, "Archivos Escaneados", "0 (0 B)")
        self.card_groups = self._create_card(metrics_frame, "Grupos Duplicados", "0")
        self.card_redundant = self._create_card(metrics_frame, "Archivos Redundantes", "0")
        self.card_recoverable = self._create_card(metrics_frame, "Espacio Recuperable", "0 B", highlight=True)

        # 5. Barra de progreso y estado
        prog_frame = ttk.Frame(main_frame)
        prog_frame.pack(fill=tk.X, pady=(0, 6))

        self.progress_bar = ttk.Progressbar(prog_frame, mode="determinate")
        self.progress_bar.pack(fill=tk.X, side=tk.TOP)

        self.status_label = ttk.Label(prog_frame, text="Listo para iniciar auditoría.", font=("Segoe UI", 8))
        self.status_label.pack(anchor="w", pady=(2, 0))

        # 6. Pestañas (Notebook)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Pestaña 1: Tabla de Duplicados
        tab_duplicates = ttk.Frame(self.notebook)
        self.notebook.add(tab_duplicates, text=" Duplicados Binarios ")

        columns = ("group", "hash", "size", "action", "path")
        self.tree = ttk.Treeview(tab_duplicates, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("group", text="Grupo")
        self.tree.heading("hash", text="Hash SHA-256")
        self.tree.heading("size", text="Tamaño")
        self.tree.heading("action", text="Acción")
        self.tree.heading("path", text="Ruta del Archivo")

        self.tree.column("group", width=65, anchor="center")
        self.tree.column("hash", width=110, anchor="center")
        self.tree.column("size", width=95, anchor="e")
        self.tree.column("action", width=110, anchor="center")
        self.tree.column("path", width=550, anchor="w")

        tree_scroll_y = ttk.Scrollbar(tab_duplicates, orient=tk.VERTICAL, command=self.tree.yview)
        tree_scroll_x = ttk.Scrollbar(tab_duplicates, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Estilos de filas
        self.tree.tag_configure("keep", background="#e6fffa", foreground="#234e52")
        self.tree.tag_configure("quarantine", background="#fffaf0", foreground="#744210")

        # Pestaña 2: Bitácora de Registro
        tab_log = ttk.Frame(self.notebook)
        self.notebook.add(tab_log, text=" Bitácora de Registro ")

        self.log_text = ScrolledText(tab_log, wrap=tk.WORD, font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _create_card(self, parent: ttk.Frame, title: str, initial_value: str, highlight: bool = False) -> ttk.Label:
        card = ttk.Frame(parent, relief=tk.RIDGE, borderwidth=1, padding=(8, 4))
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)

        ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="center")
        val_lbl = ttk.Label(
            card,
            text=initial_value,
            style="CardValue.TLabel",
            foreground="#2f855a" if highlight else "#2b6cb0"
        )
        val_lbl.pack(anchor="center")
        return val_lbl

    def _log(self, message: str):
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)

    def _browse_directory(self):
        chosen = filedialog.askdirectory(title="Seleccionar directorio a auditar")
        if chosen:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, chosen)
            self._validate_and_update_path(chosen)

    def _validate_and_update_path(self, path_str: str) -> Path | None:
        try:
            target = validate_target_path(path_str)
            self.status_label.config(text=f"Ruta segura verificada: {target}", foreground="green")
            return target
        except Exception as e:
            self.status_label.config(text=f"Seguridad: {e}", foreground="red")
            messagebox.showerror("Error de Validación de Seguridad", str(e))
            return None

    def _start_scan_thread(self):
        if self.is_processing:
            return

        path_str = self.path_entry.get().strip()
        if not path_str:
            messagebox.showwarning("Atención", "Por favor especifique o examine un directorio a auditar.")
            return

        target_dir = self._validate_and_update_path(path_str)
        if not target_dir:
            return

        self.current_base_dir = target_dir
        rule_key = self.rule_combobox.get()
        keep_rule = RULE_OPTIONS.get(rule_key, KeepRule.DEEPEST_THEN_NEWEST.value)
        try:
            workers = int(self.workers_spinbox.get())
        except ValueError:
            workers = 4

        self.is_processing = True
        self.scan_btn.config(state=tk.DISABLED)
        self.quarantine_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.DISABLED)
        self.progress_bar["value"] = 0
        self.status_label.config(text="Iniciando escaneo y análisis por tamaño...", foreground="black")

        # Limpiar tabla
        for item in self.tree.get_children():
            self.tree.delete(item)

        self._log(f"\n--- Iniciando Auditoría Dry-Run en: {target_dir} ---")
        self._log(f"Criterio: {keep_rule} | Hilos de trabajo: {workers}")

        def worker():
            def progress_cb(done, total, fname):
                pct = int((done / total) * 100) if total > 0 else 0
                self.root.after(0, lambda: self._update_progress(pct, f"Calculando SHA-256 ({done}/{total}): {fname}"))

            duplicates, summary = scan_directory_for_duplicates(
                base_dir=target_dir,
                max_workers=workers,
                progress_callback=progress_cb
            )

            report = generate_report_dict(
                base_dir=target_dir,
                duplicates=duplicates,
                summary=summary,
                keep_rule=keep_rule
            )

            self.root.after(0, lambda: self._on_scan_completed(duplicates, summary, report))

        threading.Thread(target=worker, daemon=True).start()

    def _update_progress(self, percent: int, text: str):
        self.progress_bar["value"] = percent
        self.status_label.config(text=text)

    def _on_scan_completed(self, duplicates: dict, summary: ScanSummary, report: dict):
        self.is_processing = False
        self.scan_btn.config(state=tk.NORMAL)
        self.last_duplicates = duplicates
        self.last_summary = summary
        self.last_report = report

        meta = report["metadata"]
        self.card_files.config(text=f"{meta['total_files_scanned']:,} ({meta['total_bytes_scanned_formatted']})")
        self.card_groups.config(text=str(meta["duplicate_groups"]))
        self.card_redundant.config(text=str(meta["total_redundant_files"]))
        self.card_recoverable.config(text=meta["recoverable_formatted"])

        # Poblar Treeview
        for idx, g in enumerate(report["groups"], start=1):
            short_hash = g["hash_sha256"][:12] + "…"
            f_size = g["file_size_formatted"]

            # Fila de conservación
            self.tree.insert(
                "",
                tk.END,
                values=(f"#{idx}", short_hash, f_size, "KEEP (Conservar)", g["kept_file"]),
                tags=("keep",)
            )

            # Filas de cuarentena
            for q_file in g["quarantine_files"]:
                self.tree.insert(
                    "",
                    tk.END,
                    values=("", "", "", "QUARANTINE", q_file),
                    tags=("quarantine",)
                )

        if meta["total_redundant_files"] > 0:
            self.quarantine_btn.config(state=tk.NORMAL)
            self.status_label.config(
                text=f"Simulación completa: {meta['total_redundant_files']} archivos redundantes detectados. "
                     f"Espacio recuperable: {meta['recoverable_formatted']}.",
                foreground="blue"
            )
        else:
            self.status_label.config(
                text="Auditoría completa: No se encontraron archivos duplicados.",
                foreground="green"
            )

        self.export_btn.config(state=tk.NORMAL)
        self._log(f"Auditoría finalizada. Grupos: {meta['duplicate_groups']} | Redundantes: {meta['total_redundant_files']} | Recuperable: {meta['recoverable_formatted']}")

    def _execute_quarantine(self):
        if not self.last_report or not self.current_base_dir:
            return

        total_redundant = self.last_report["metadata"]["total_redundant_files"]
        rec_str = self.last_report["metadata"]["recoverable_formatted"]

        # Principio 1.2: Confirmación obligatoria previa
        resp = messagebox.askyesno(
            "Confirmar Aislamiento en Cuarentena (Soft-Delete)",
            f"¿Desea mover los {total_redundant} archivos redundantes ({rec_str}) a la carpeta de Cuarentena?\n\n"
            f"Principio de Seguridad Cero Pérdida:\n"
            f"• Los archivos NO se borrarán con os.remove.\n"
            f"• Se trasladarán preservando su árbol relativo a una carpeta '_quarantine_...'\n"
            f"• Se creará un manifest.json que permite revertir la operación en cualquier momento.",
            icon="warning"
        )
        if not resp:
            return

        rule_key = self.rule_combobox.get()
        keep_rule = RULE_OPTIONS.get(rule_key, KeepRule.DEEPEST_THEN_NEWEST.value)
        plan = build_audit_plan(self.last_duplicates, keep_rule=keep_rule)

        try:
            res: QuarantineResult = quarantine_redundant_files(self.current_base_dir, plan)
            self._log(f"\n✔ Cuarentena ejecutada: {res.total_moved} archivos trasladados a {res.quarantine_dir}")
            self._log(f"  Manifiesto generado: {res.manifest_path}")

            messagebox.showinfo(
                "Cuarentena Completada",
                f"Se trasladaron {res.total_moved} archivos ({format_bytes(res.total_bytes_moved)}) a:\n"
                f"{res.quarantine_dir}\n\n"
                f"El archivo de manifiesto reversible se guardó en:\n{res.manifest_path}"
            )
            self.quarantine_btn.config(state=tk.DISABLED)
            self._start_scan_thread()  # Re-escanear para actualizar estado limpio
        except Exception as e:
            messagebox.showerror("Error en Cuarentena", f"Ocurrió un error: {e}")

    def _restore_from_manifest(self):
        manifest_file = filedialog.askopenfilename(
            title="Seleccionar manifest.json de Cuarentena",
            filetypes=[("Archivo Manifiesto JSON", "manifest*.json"), ("Todos los archivos", "*.*")]
        )
        if not manifest_file:
            return

        try:
            res: RestoreResult = restore_from_quarantine(manifest_file)
            self._log(f"\n✔ Restauración completada: {res.total_restored} archivos devueltos a sus ubicaciones originales.")
            if res.errors:
                for err in res.errors:
                    self._log(f"  [ERROR] {err}")

            messagebox.showinfo(
                "Restauración Completada",
                f"Se restauraron {res.total_restored} archivos ({format_bytes(res.total_bytes_restored)}).\n"
                f"Archivos omitidos previamente restaurados: {res.skipped_count}\n"
                f"Errores: {len(res.errors)}"
            )

            # Si el directorio objetivo actual está cargado, re-escanear
            if self.current_base_dir:
                self._start_scan_thread()

        except Exception as e:
            messagebox.showerror("Error al Restaurar", f"No se pudo completar la restauración: {e}")

    def _export_json_report(self):
        if not self.last_report:
            return

        save_path = filedialog.asksaveasfilename(
            title="Guardar Reporte de Auditoría",
            defaultextension=".json",
            filetypes=[("Archivos JSON", "*.json")]
        )
        if save_path:
            export_report_json(self.last_report, save_path)
            messagebox.showinfo("Exportación Exitosa", f"Reporte guardado en:\n{save_path}")

def launch_gui(initial_dir: str | None = None):
    root = tk.Tk()
    app = DataCleanerGUI(root, initial_dir=initial_dir)
    root.mainloop()

if __name__ == "__main__":
    launch_gui()
