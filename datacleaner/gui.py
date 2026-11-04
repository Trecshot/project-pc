"""
Interfaz Gráfica de Usuario de Escritorio (Fluent Design con Sun Valley TTK)
DataCleaner GUI

Implementación bajo arquitectura Zero-Class-Rewrite sobre ttk estándar,
inyectando el tema Sun Valley (Fluent Design Windows 11) mediante sv-ttk.
Incluye modal interactivo de restauración por sesiones (RestoreModal),
soporte nativo de modo oscuro/claro, validación en línea de rutas,
tarjetas Card.TFrame de alto contraste (WCAG) y Call to Action con estilo Accent.TButton.
"""

import os
import threading
from pathlib import Path
from typing import Any, Callable
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

try:
    import sv_ttk
    HAS_SV_TTK = True
except ImportError:
    HAS_SV_TTK = False

from datacleaner.security import validate_target_path
from datacleaner.scanner import scan_directory_for_duplicates, ScanSummary
from datacleaner.rules import KeepRule
from datacleaner.hasher import get_safe_worker_count
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
    format_bytes,
    export_report_json
)

RULE_OPTIONS = {
    "Ruta más profunda y limpia, luego más reciente (Recomendado)": KeepRule.DEEPEST_THEN_NEWEST.value,
    "Ruta más profunda y limpia, luego más antigua": KeepRule.DEEPEST_THEN_OLDEST.value,
    "Ruta más superficial, luego más reciente": KeepRule.SHALLOWEST_THEN_NEWEST.value,
    "Solo el archivo más reciente": KeepRule.NEWEST_ONLY.value,
    "Solo el archivo más antiguo": KeepRule.OLDEST_ONLY.value,
}

class RestoreModal(tk.Toplevel):
    """
    Modal Toplevel exclusivo para selección y restauración de sesiones de cuarentena.
    Escanea carpetas _quarantine_* locales y presenta un Treeview tabular sin requerir
    conocimientos técnicos del sistema de archivos subyacente.
    """
    def __init__(
        self,
        parent: tk.Tk | tk.Widget,
        base_dir: Path | str,
        on_restore_success: Callable[[], None] | None = None
    ):
        super().__init__(parent)
        self.parent = parent
        self.base_dir = Path(base_dir).resolve().absolute()
        self.on_restore_success = on_restore_success

        self.title("Restaurar Sesión de Cuarentena - DataCleaner")
        self.geometry("780x520")
        self.minsize(660, 420)

        # Modal exclusivo sobre la ventana principal
        self.transient(parent)
        self.grab_set()

        self.sessions: list[dict] = []
        self.selected_session: dict | None = None

        self._build_ui()
        self._load_sessions()

    def _build_ui(self):
        container = ttk.Frame(self, padding=(20, 16))
        container.pack(fill="both", expand=True)

        # 1. Área de Instrucción
        ttk.Label(
            container,
            text="Restauración de Cuarentena",
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w")

        ttk.Label(
            container,
            text="Seleccione una sesión de cuarentena para devolver los archivos a su ubicación original.",
            font=("Segoe UI", 10)
        ).pack(anchor="w", pady=(2, 10))

        # Directorio base explorado con opción de cambio
        dir_frame = ttk.Frame(container, style="Card.TFrame", padding=(10, 6))
        dir_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(
            dir_frame,
            text="Directorio auditado:",
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=(0, 6))

        self.dir_lbl = ttk.Label(
            dir_frame,
            text=str(self.base_dir),
            font=("Segoe UI", 9)
        )
        self.dir_lbl.pack(side="left", fill="x", expand=True)

        change_dir_btn = ttk.Button(
            dir_frame,
            text="Cambiar...",
            command=self._change_search_dir,
            width=10
        )
        change_dir_btn.pack(side="right")

        # 2. Treeview de Sesiones (Tabla)
        # Columna 1: Fecha y Hora | Columna 2: Cantidad de Archivos | Columna 3: Espacio Total
        table_frame = ttk.Frame(container)
        table_frame.pack(fill="both", expand=True, pady=(0, 10))

        columns = ("timestamp", "files", "bytes", "session")
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
            style="Data.Treeview"
        )

        self.tree.heading("timestamp", text="Fecha y Hora")
        self.tree.heading("files", text="Cantidad de Archivos")
        self.tree.heading("bytes", text="Espacio Total")
        self.tree.heading("session", text="Sesión")

        self.tree.column("timestamp", width=180, anchor="center")
        self.tree.column("files", width=150, anchor="center")
        self.tree.column("bytes", width=130, anchor="e")
        self.tree.column("session", width=220, anchor="w")

        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll_y.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self._on_session_selected)

        # 3. Resumen Dinámico de Selección
        self.summary_card = ttk.Frame(container, style="Card.TFrame", padding=(12, 8))
        self.summary_card.pack(fill="x", pady=(0, 12))

        self.summary_lbl = ttk.Label(
            self.summary_card,
            text="Ninguna sesión seleccionada. Haga clic en una fila de la tabla.",
            font=("Segoe UI", 9, "bold")
        )
        self.summary_lbl.pack(anchor="w")

        # 4. Barra de Progreso
        self.prog_bar = ttk.Progressbar(container, mode="indeterminate")

        # 5. Botones de Acción
        btn_bar = ttk.Frame(container)
        btn_bar.pack(fill="x")

        self.restore_btn = ttk.Button(
            btn_bar,
            text="Restaurar Sesión Seleccionada",
            style="Accent.TButton",
            state="disabled",
            command=self._execute_restore
        )
        self.restore_btn.pack(side="left", padx=(0, 10))

        cancel_btn = ttk.Button(
            btn_bar,
            text="Cancelar",
            command=self.destroy
        )
        cancel_btn.pack(side="left")

        manual_btn = ttk.Button(
            btn_bar,
            text="Examinar manifest.json...",
            command=self._browse_manual_manifest
        )
        manual_btn.pack(side="right")

    def _load_sessions(self):
        """Escanea localmente las carpetas _quarantine_* y carga los metadatos."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.selected_session = None
        self.restore_btn.configure(state="disabled")

        self.sessions = find_quarantine_sessions(self.base_dir)

        if not self.sessions:
            self.summary_lbl.configure(
                text="No se encontraron sesiones de cuarentena (_quarantine_*) en este directorio."
            )
            return

        for idx, s in enumerate(self.sessions):
            self.tree.insert(
                "",
                tk.END,
                iid=str(idx),
                values=(
                    s["timestamp"],
                    f"{s['total_files']} archivos",
                    s["total_bytes_formatted"],
                    s["session_id"]
                )
            )

        self.summary_lbl.configure(
            text=f"Se encontraron {len(self.sessions)} sesiones disponibles. Seleccione una para ver su detalle."
        )

    def _on_session_selected(self, event):
        selected = self.tree.selection()
        if not selected:
            self.selected_session = None
            self.restore_btn.configure(state="disabled")
            self.summary_lbl.configure(text="Ninguna sesión seleccionada.")
            return

        idx = int(selected[0])
        self.selected_session = self.sessions[idx]

        # Resumen visual dinámico: Ej. "569 archivos, 437.14 KB"
        s = self.selected_session
        self.summary_lbl.configure(
            text=f"Sesión seleccionada: {s['total_files']} archivos, {s['total_bytes_formatted']} "
                 f"({s['timestamp']}) en {s['folder_name']}"
        )
        self.restore_btn.configure(state="normal")

    def _change_search_dir(self):
        chosen = filedialog.askdirectory(title="Seleccionar directorio donde buscar cuarentenas", parent=self)
        if chosen:
            self.base_dir = Path(chosen).resolve().absolute()
            self.dir_lbl.configure(text=str(self.base_dir))
            self._load_sessions()

    def _browse_manual_manifest(self):
        manifest_file = filedialog.askopenfilename(
            title="Seleccionar archivo manifest.json",
            filetypes=[("Archivo Manifiesto JSON", "manifest*.json"), ("Todos los archivos", "*.*")],
            parent=self
        )
        if manifest_file:
            self._do_restore(manifest_file)

    def _execute_restore(self):
        if not self.selected_session:
            return

        s = self.selected_session
        confirm = messagebox.askyesno(
            "Confirmar Restauración Reversible",
            f"¿Desea restaurar la sesión '{s['session_id']}'?\n\n"
            f"• Archivos a devolver a su origen: {s['total_files']}\n"
            f"• Espacio a recuperar: {s['total_bytes_formatted']}\n\n"
            f"Al finalizar, la carpeta de cuarentena vacía será eliminada automáticamente.",
            icon="question",
            parent=self
        )
        if not confirm:
            return

        self._do_restore(s["manifest_path"])

    def _do_restore(self, manifest_path: Path | str):
        self.restore_btn.configure(state="disabled")
        self.prog_bar.pack(fill="x", pady=(0, 8))
        self.prog_bar.start()

        def worker():
            try:
                res = restore_from_quarantine(manifest_path)
                self.after(0, lambda: self._on_restore_done(res))
            except Exception as e:
                self.after(0, lambda: self._on_restore_error(e))

        threading.Thread(target=worker, daemon=True).start()

    def _on_restore_done(self, res: RestoreResult):
        self.prog_bar.stop()
        self.prog_bar.pack_forget()

        msg = f"Se restauraron exitosamente {res.total_restored} archivos ({format_bytes(res.total_bytes_restored)}) a sus ubicaciones originales."
        if res.quarantine_folder_removed:
            msg += "\n\n✔ La carpeta de cuarentena vacía ha sido eliminada del disco."

        if res.errors:
            msg += f"\n\nAdvertencias / Conflictos ({len(res.errors)}):\n"
            for err in res.errors[:3]:
                msg += f"• {err}\n"

        messagebox.showinfo("Restauración Completada", msg, parent=self)

        if self.on_restore_success:
            self.on_restore_success()

        self.destroy()

    def _on_restore_error(self, exc: Exception):
        self.prog_bar.stop()
        self.prog_bar.pack_forget()
        self.restore_btn.configure(state="normal")
        messagebox.showerror("Error al Restaurar", f"No se pudo completar la restauración: {exc}", parent=self)


class DataCleanerGUI:
    def __init__(self, root: tk.Tk, initial_dir: str | None = None):
        self.root = root
        self.root.title("DataCleaner - Auditoría y Organización de Archivos")
        self.root.geometry("1100x780")
        self.root.minsize(860, 600)

        # 1. Inyección de Tema Sun Valley (Fluent Design Windows 11)
        self.current_theme = "dark"
        self._apply_sun_valley_theme()

        # Estado del modelo
        self.current_base_dir: Path | None = None
        self.last_duplicates: dict[str, list[Path]] = {}
        self.last_summary: ScanSummary | None = None
        self.last_report: dict[str, Any] | None = None
        self.is_processing = False
        self.is_advanced_open = False

        # 2. Inicialización de componentes sobre ttk estándar (Zero-Class-Rewrite)
        self._build_interface()

        if initial_dir:
            self.path_entry.insert(0, str(initial_dir))
            self._validate_path_input(str(initial_dir))

    def _apply_sun_valley_theme(self):
        """Aplica el tema Sun Valley o fallback a clam si no estuviese instalado."""
        if HAS_SV_TTK:
            try:
                sv_ttk.set_theme(self.current_theme)
            except Exception:
                pass
        else:
            style = ttk.Style(self.root)
            try:
                style.theme_use("clam")
            except Exception:
                pass

        self._configure_custom_styles()

    def _configure_custom_styles(self):
        """Configuración de tipografías y colores de alto contraste WCAG."""
        style = ttk.Style(self.root)

        style.configure("HeaderTitle.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("HeaderSubtitle.TLabel", font=("Segoe UI", 10))
        style.configure("CardTitle.TLabel", font=("Segoe UI", 9, "bold"))
        style.configure("CardValue.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("AccentValue.TLabel", font=("Segoe UI", 18, "bold"))

        style.configure("Data.Treeview", rowheight=28, font=("Segoe UI", 9))
        style.configure("Data.Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _toggle_theme(self):
        """Conmutación centralizada de tema oscuro / claro."""
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        if HAS_SV_TTK:
            sv_ttk.set_theme(self.current_theme)
        self._configure_custom_styles()
        self._update_tag_colors()

    def _build_interface(self):
        self.main_frame = ttk.Frame(self.root, padding=(20, 16))
        self.main_frame.pack(fill="both", expand=True)

        self._build_header()
        self._build_selection_card()
        self._build_action_bar()
        self._build_dashboard_cards()
        self._build_progress_area()
        self._build_notebook_tabs()

    def _build_header(self):
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill="x", pady=(0, 12))

        text_frame = ttk.Frame(header_frame)
        text_frame.pack(side="left", fill="x", expand=True)

        ttk.Label(
            text_frame,
            text="DataCleaner",
            style="HeaderTitle.TLabel"
        ).pack(anchor="w")

        ttk.Label(
            text_frame,
            text="1. Seleccione una carpeta.  2. Escanee en busca de duplicados.  Ningún archivo será borrado sin su confirmación.",
            style="HeaderSubtitle.TLabel"
        ).pack(anchor="w", pady=(2, 0))

        theme_btn = ttk.Button(
            header_frame,
            text="🌓 Tema",
            command=self._toggle_theme,
            width=8
        )
        theme_btn.pack(side="right", anchor="e")

    def _build_selection_card(self):
        self.card_selection = ttk.Frame(self.main_frame, style="Card.TFrame", padding=14)
        self.card_selection.pack(fill="x", pady=(0, 12))

        row_browse = ttk.Frame(self.card_selection)
        row_browse.pack(fill="x", pady=(0, 6))

        ttk.Label(
            row_browse,
            text="Carpeta a auditar:",
            font=("Segoe UI", 10, "bold")
        ).pack(side="left", padx=(0, 8))

        self.path_entry = ttk.Entry(row_browse, font=("Segoe UI", 10))
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.path_entry.bind("<KeyRelease>", self._on_path_key_release)

        browse_btn = ttk.Button(
            row_browse,
            text="Examinar...",
            command=self._browse_directory,
            width=14
        )
        browse_btn.pack(side="left")

        # Texto de validación en línea
        self.validation_label = ttk.Label(
            self.card_selection,
            text="Por favor seleccione una carpeta para comenzar.",
            font=("Segoe UI", 9)
        )
        self.validation_label.pack(anchor="w", pady=(0, 6))

        # Opciones avanzadas
        self.adv_btn = ttk.Button(
            self.card_selection,
            text="⚙ Opciones avanzadas ▼",
            command=self._toggle_advanced_options,
            width=22
        )
        self.adv_btn.pack(anchor="w")

        self.advanced_frame = ttk.Frame(self.card_selection, padding=(0, 8))
        row_adv = ttk.Frame(self.advanced_frame)
        row_adv.pack(fill="x")

        ttk.Label(
            row_adv,
            text="Criterio de Permanencia:",
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=(0, 6))

        self.rule_combobox = ttk.Combobox(
            row_adv,
            values=list(RULE_OPTIONS.keys()),
            state="readonly",
            width=48,
            font=("Segoe UI", 9)
        )
        self.rule_combobox.current(0)
        self.rule_combobox.pack(side="left", padx=(0, 16))

        default_workers = get_safe_worker_count()
        ttk.Label(
            row_adv,
            text=f"Hilos I/O: {default_workers} (Automático según CPU)",
            font=("Segoe UI", 9)
        ).pack(side="left")

    def _build_action_bar(self):
        action_bar = ttk.Frame(self.main_frame)
        action_bar.pack(fill="x", pady=(0, 12))

        # CTA Principal
        self.scan_btn = ttk.Button(
            action_bar,
            text="🔍 Iniciar Simulación",
            style="Accent.TButton",
            command=self._start_scan_thread,
            state="disabled"
        )
        self.scan_btn.pack(side="left", padx=(0, 8))

        # Botón Cuarentena
        self.quarantine_btn = ttk.Button(
            action_bar,
            text="📦 Enviar a Cuarentena",
            command=self._execute_quarantine,
            state="disabled"
        )
        self.quarantine_btn.pack(side="left", padx=(0, 8))

        # Botón Restaurar -> Inicia el Flujo de Selección de Sesión (RestoreModal)
        self.restore_btn = ttk.Button(
            action_bar,
            text="🔄 Restaurar desde Cuarentena",
            command=self._open_restore_modal
        )
        self.restore_btn.pack(side="left", padx=(0, 8))

        # Botón Exportar JSON
        self.export_btn = ttk.Button(
            action_bar,
            text="💾 Exportar JSON",
            command=self._export_json_report,
            state="disabled"
        )
        self.export_btn.pack(side="right")

    def _build_dashboard_cards(self):
        cards_frame = ttk.Frame(self.main_frame)
        cards_frame.pack(fill="x", pady=(0, 12))

        self.card_files = self._create_card(cards_frame, "Archivos Analizados", "0 (0 B)")
        self.card_groups = self._create_card(cards_frame, "Grupos Duplicados", "0")
        self.card_redundant = self._create_card(cards_frame, "Copias Redundantes", "0")
        self.card_recoverable = self._create_card(cards_frame, "Espacio Recuperable", "0 B", is_accent=True)

    def _create_card(self, parent: ttk.Frame, title: str, initial_val: str, is_accent: bool = False) -> ttk.Label:
        card = ttk.Frame(parent, style="Card.TFrame", padding=(12, 10))
        card.pack(side="left", fill="both", expand=True, padx=4)

        ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="center")
        val_lbl = ttk.Label(
            card,
            text=initial_val,
            style="AccentValue.TLabel" if is_accent else "CardValue.TLabel"
        )
        val_lbl.pack(anchor="center", pady=(4, 0))
        return val_lbl

    def _build_progress_area(self):
        prog_frame = ttk.Frame(self.main_frame)
        prog_frame.pack(fill="x", pady=(0, 10))

        self.progress_bar = ttk.Progressbar(prog_frame, mode="determinate")
        self.progress_bar.pack(fill="x", pady=(0, 4))

        self.status_label = ttk.Label(
            prog_frame,
            text="Listo para iniciar auditoría.",
            font=("Segoe UI", 9)
        )
        self.status_label.pack(anchor="w")

    def _build_notebook_tabs(self):
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill="both", expand=True)

        tab_dups = ttk.Frame(self.notebook, padding=4)
        tab_log = ttk.Frame(self.notebook, padding=4)

        self.notebook.add(tab_dups, text=" Duplicados Encontrados ")
        self.notebook.add(tab_log, text=" Bitácora de Registro ")

        table_container = ttk.Frame(tab_dups)
        table_container.pack(fill="both", expand=True)

        columns = ("group", "action", "size", "hash_short", "path")
        self.tree = ttk.Treeview(
            table_container,
            columns=columns,
            show="headings",
            selectmode="browse",
            style="Data.Treeview"
        )

        self.tree.heading("group", text="Grupo")
        self.tree.heading("action", text="Acción")
        self.tree.heading("size", text="Tamaño")
        self.tree.heading("hash_short", text="Hash (8 car.)")
        self.tree.heading("path", text="Ruta del Archivo")

        self.tree.column("group", width=65, anchor="center")
        self.tree.column("action", width=140, anchor="center")
        self.tree.column("size", width=100, anchor="e")
        self.tree.column("hash_short", width=105, anchor="center")
        self.tree.column("path", width=580, anchor="w")

        scroll_y = ttk.Scrollbar(table_container, orient="vertical", command=self.tree.yview)
        scroll_x = ttk.Scrollbar(table_container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        self.tree.pack(side="left", fill="both", expand=True)

        self._update_tag_colors()

        self.log_text = ScrolledText(
            tab_log,
            wrap="word",
            font=("Consolas", 9),
            padx=8,
            pady=8
        )
        self.log_text.pack(fill="both", expand=True)

    def _update_tag_colors(self):
        is_dark = (self.current_theme == "dark")
        keep_bg = "#0f392b" if is_dark else "#d1fae5"
        keep_fg = "#a7f3d0" if is_dark else "#065f46"
        quar_bg = "#451a03" if is_dark else "#fef3c7"
        quar_fg = "#fde68a" if is_dark else "#92400e"

        self.tree.tag_configure("keep", background=keep_bg, foreground=keep_fg)
        self.tree.tag_configure("quarantine", background=quar_bg, foreground=quar_fg)

    def _toggle_advanced_options(self):
        if self.is_advanced_open:
            self.advanced_frame.pack_forget()
            self.adv_btn.configure(text="⚙ Opciones avanzadas ▼")
            self.is_advanced_open = False
        else:
            self.advanced_frame.pack(fill="x", pady=(6, 0))
            self.adv_btn.configure(text="⚙ Opciones avanzadas ▲")
            self.is_advanced_open = True

    def _on_path_key_release(self, event):
        path_str = self.path_entry.get().strip()
        self._validate_path_input(path_str)

    def _browse_directory(self):
        chosen = filedialog.askdirectory(title="Seleccionar carpeta a auditar")
        if chosen:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, chosen)
            self._validate_path_input(chosen)

    def _validate_path_input(self, path_str: str) -> bool:
        if not path_str:
            self.validation_label.configure(
                text="Por favor seleccione una carpeta para comenzar."
            )
            self.scan_btn.configure(state="disabled")
            self.current_base_dir = None
            return False

        try:
            validated = validate_target_path(path_str)
            self.validation_label.configure(
                text=f"✔ Carpeta válida y segura para auditar: {validated}"
            )
            self.scan_btn.configure(state="normal")
            self.current_base_dir = validated
            return True
        except PermissionError as pe:
            self.validation_label.configure(
                text=f"⛔ Protegido por el sistema: {pe}"
            )
            self.scan_btn.configure(state="disabled")
            self.current_base_dir = None
            return False
        except FileNotFoundError:
            self.validation_label.configure(
                text="⚠ La carpeta especificada no existe en el almacenamiento."
            )
            self.scan_btn.configure(state="disabled")
            self.current_base_dir = None
            return False
        except Exception as e:
            self.validation_label.configure(
                text=f"⚠ Ruta no válida: {e}"
            )
            self.scan_btn.configure(state="disabled")
            self.current_base_dir = None
            return False

    def _log(self, text: str):
        self.log_text.insert(tk.END, f"{text}\n")
        self.log_text.see(tk.END)

    def _start_scan_thread(self):
        if self.is_processing or not self.current_base_dir:
            return

        target_dir = self.current_base_dir
        rule_key = self.rule_combobox.get()
        keep_rule = RULE_OPTIONS.get(rule_key, KeepRule.DEEPEST_THEN_NEWEST.value)
        workers = get_safe_worker_count()

        self.is_processing = True
        self.scan_btn.configure(state="disabled")
        self.quarantine_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.progress_bar["value"] = 0
        self.status_label.configure(text="Iniciando escaneo y análisis por tamaño...")

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
        self.status_label.configure(text=text)

    def _on_scan_completed(self, duplicates: dict, summary: ScanSummary, report: dict):
        self.is_processing = False
        self.scan_btn.configure(state="normal")
        self.last_duplicates = duplicates
        self.last_summary = summary
        self.last_report = report

        meta = report["metadata"]
        self.card_files.configure(text=f"{meta['total_files_scanned']:,} ({meta['total_bytes_scanned_formatted']})")
        self.card_groups.configure(text=str(meta["duplicate_groups"]))
        self.card_redundant.configure(text=str(meta["total_redundant_files"]))
        self.card_recoverable.configure(text=meta["recoverable_formatted"])

        for idx, g in enumerate(report["groups"], start=1):
            short_hash = g["hash_sha256"][:8] + "…"
            f_size = g["file_size_formatted"]

            self.tree.insert(
                "",
                tk.END,
                values=(f"#{idx}", "KEEP (Conservar)", f_size, short_hash, g["kept_file"]),
                tags=("keep",)
            )

            for q_file in g["quarantine_files"]:
                self.tree.insert(
                    "",
                    tk.END,
                    values=("", "QUARANTINE", "", "", q_file),
                    tags=("quarantine",)
                )

        if meta["total_redundant_files"] > 0:
            self.quarantine_btn.configure(state="normal", style="Accent.TButton")
            self.status_label.configure(
                text=f"Simulación completa: {meta['total_redundant_files']} archivos redundantes detectados. "
                     f"Espacio recuperable: {meta['recoverable_formatted']}."
            )
        else:
            self.quarantine_btn.configure(style="TButton")
            self.status_label.configure(
                text="Auditoría completa: No se encontraron archivos duplicados. El almacenamiento está limpio."
            )

        self.export_btn.configure(state="normal")
        self._log(f"Auditoría finalizada. Grupos: {meta['duplicate_groups']} | Redundantes: {meta['total_redundant_files']} | Recuperable: {meta['recoverable_formatted']}")

    def _execute_quarantine(self):
        if not self.last_report or not self.current_base_dir:
            return

        total_redundant = self.last_report["metadata"]["total_redundant_files"]
        rec_str = self.last_report["metadata"]["recoverable_formatted"]

        resp = messagebox.askyesno(
            "Confirmar Cuarentena (Soft-Delete)",
            f"¿Desea mover {total_redundant} archivos duplicados ({rec_str}) a la carpeta de aislamiento?\n\n"
            f"Garantía de Cero Pérdida de Datos:\n"
            f"• Los archivos NO serán borrados permanentemente.\n"
            f"• Se trasladarán a una carpeta de cuarentena preservando su estructura.\n"
            f"• Podrá restaurarlos en cualquier momento desde el botón 'Restaurar'.",
            icon="question"
        )
        if not resp:
            return

        rule_key = self.rule_combobox.get()
        keep_rule = RULE_OPTIONS.get(rule_key, KeepRule.DEEPEST_THEN_NEWEST.value)
        plan = build_audit_plan(self.last_duplicates, keep_rule=keep_rule)

        try:
            res: QuarantineResult = quarantine_redundant_files(self.current_base_dir, plan)
            self._log(f"\n✔ Cuarentena completada: {res.total_moved} archivos trasladados a {res.quarantine_dir}")
            self._log(f"  Manifiesto generado: {res.manifest_path}")

            messagebox.showinfo(
                "Cuarentena Exitosa",
                f"Se trasladaron {res.total_moved} archivos ({format_bytes(res.total_bytes_moved)}) a la carpeta de cuarentena.\n\n"
                f"Sesión: {res.session_id}\n"
                f"Ubicación:\n{res.quarantine_dir}\n\n"
                f"Puede restaurarlos en cualquier momento utilizando el botón 'Restaurar desde Cuarentena'."
            )
            self.quarantine_btn.configure(state="disabled", style="TButton")
            self._start_scan_thread()
        except Exception as e:
            messagebox.showerror("Error en Cuarentena", f"Ocurrió un error al mover los archivos: {e}")

    def _open_restore_modal(self):
        """
        Fase 1 y 2: Invocación y apertura del Modal de Restauración Reversible (RestoreModal).
        Explora las sesiones locales _quarantine_* del directorio actual.
        """
        search_dir = self.current_base_dir or Path.cwd()
        RestoreModal(
            parent=self.root,
            base_dir=search_dir,
            on_restore_success=self._on_modal_restore_success
        )

    def _on_modal_restore_success(self):
        """Callback invocado tras una restauración exitosa en el modal."""
        self._log("\n✔ Restauración de sesión ejecutada exitosamente desde el modal interactivo.")
        if self.current_base_dir:
            self._start_scan_thread()

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
            messagebox.showinfo("Exportación Exitosa", f"El reporte fue guardado correctamente en:\n{save_path}")

def launch_gui(initial_dir: str | None = None):
    root = tk.Tk()
    app = DataCleanerGUI(root, initial_dir=initial_dir)
    root.mainloop()

if __name__ == "__main__":
    launch_gui()
