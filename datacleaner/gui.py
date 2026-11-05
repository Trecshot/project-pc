"""
Interfaz Gráfica de Usuario de Escritorio (Fluent Design con Sun Valley TTK)
DataCleaner GUI — Edición Moderna y Accesible (WCAG 2.1 AA)

Implementación bajo arquitectura Zero-Class-Rewrite sobre ttk estándar,
inyectando el tema Sun Valley (Fluent Design Windows 11) mediante sv-ttk.
Incluye:
- Barra de título nativa inmersiva Windows 11 (modo oscuro / claro vía DWM API)
- Accesos rápidos a carpetas de usuario (Descargas, Documentos, Imágenes, Escritorio)
- Validación en línea semántica por colores (WCAG AA)
- Tarjetas KPI con jerarquía visual, acentos de color y subtítulos descriptivos
- Barra de búsqueda y filtrado en vivo de duplicados + menú contextual y doble clic
- Modal interactivo de gestión de cuarentena (Restaurar / Purgar / Vaciar todo)
- Atajos de teclado globales (F5, Ctrl+O, Ctrl+G, Ctrl+E, Ctrl+T, Ctrl+F)
"""

import os
import sys
import subprocess
import threading
import ctypes
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
    purge_quarantine_session,
    purge_all_quarantine_sessions,
    delete_redundant_files,
    execute_deletion_plan,
    QuarantineResult,
    RestoreResult,
    DeleteResult,
    HAS_SEND2TRASH
)
from datacleaner.reporter import (
    build_audit_plan,
    generate_report_dict,
    format_bytes,
    export_report_json
)
from datacleaner.history import (
    CleaningHistoryManager,
    format_bytes_auto,
    format_bytes_with_equivalence
)

RULE_OPTIONS = {
    "Ruta más profunda y limpia, luego más reciente (Recomendado)": KeepRule.DEEPEST_THEN_NEWEST.value,
    "Ruta más profunda y limpia, luego más antigua": KeepRule.DEEPEST_THEN_OLDEST.value,
    "Ruta más superficial, luego más reciente": KeepRule.SHALLOWEST_THEN_NEWEST.value,
    "Solo el archivo más reciente": KeepRule.NEWEST_ONLY.value,
    "Solo el archivo más antiguo": KeepRule.OLDEST_ONLY.value,
}


def apply_windows_titlebar_theme(window: tk.Tk | tk.Toplevel, is_dark: bool):
    """Aplica el modo oscuro/claro nativo de Windows 10/11 a la barra de título de la ventana."""
    if sys.platform != "win32":
        return
    try:
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        if not hwnd:
            hwnd = window.winfo_id()
        val = ctypes.c_int(1 if is_dark else 0)
        # DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (Windows 11 / Win10 20H1+)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 20, ctypes.byref(val), ctypes.sizeof(val)
        )
    except Exception:
        pass


class RestoreModal(tk.Toplevel):
    """
    Modal Toplevel exclusivo para selección, restauración y purgado de sesiones de cuarentena.
    Escanea carpetas _quarantine_* locales y presenta un Treeview tabular accesible.
    """
    def __init__(
        self,
        parent: tk.Tk | tk.Widget,
        base_dir: Path | str,
        on_restore_success: Callable[[], None] | None = None,
        is_dark: bool = True,
        history_manager: CleaningHistoryManager | None = None
    ):
        super().__init__(parent)
        self.parent = parent
        self.base_dir = Path(base_dir).resolve().absolute()
        self.on_restore_success = on_restore_success
        self.is_dark = is_dark
        self.history_manager = history_manager or CleaningHistoryManager()

        self.title("Gestor de Sesiones de Cuarentena - DataCleaner")
        self.geometry("840x550")
        self.minsize(720, 460)

        # Modal exclusivo sobre la ventana principal
        self.transient(parent)
        self.grab_set()

        self.sessions: list[dict] = []
        self.selected_session: dict | None = None

        self._build_ui()
        self._load_sessions()
        apply_windows_titlebar_theme(self, self.is_dark)

        self.bind("<Escape>", lambda e: self.destroy())

    def _build_ui(self):
        # 1. Contenedor inferior de acciones (side="bottom" para garantizar visibilidad y altura completa)
        action_bar = ttk.Frame(self, padding=(20, 14))
        action_bar.pack(side="bottom", fill="x")

        # 1.1 Botón Principal: Restaurar (Acción Primaria)
        self.restore_btn = ttk.Button(
            action_bar,
            text="🔄 Restaurar Sesión",
            style="Accent.TButton",
            state="disabled",
            command=self._execute_restore
        )
        self.restore_btn.pack(side="left", padx=(0, 10))

        # 1.2 Botón de Purga Individual (Acción Destructiva 1)
        self.purge_btn = ttk.Button(
            action_bar,
            text="🗑️ Purgar Sesión",
            state="disabled",
            command=self._execute_purge
        )
        self.purge_btn.pack(side="left", padx=(0, 10))

        # 1.3 Botón de Purga Total (Acción Destructiva 2)
        self.purge_all_btn = ttk.Button(
            action_bar,
            text="⚠️ Vaciar Todo",
            state="disabled",
            command=self._execute_purge_all
        )
        self.purge_all_btn.pack(side="left", padx=(0, 10))

        # 1.4 Botón de Cierre a la derecha (Salida)
        close_btn = ttk.Button(
            action_bar,
            text="Cerrar (Esc)",
            command=self.destroy
        )
        close_btn.pack(side="right")

        # 2. Contenedor Central para la información y tabla de sesiones
        container = ttk.Frame(self, padding=(20, 16))
        container.pack(fill="both", expand=True)

        # 2.1 Área de Instrucción
        ttk.Label(
            container,
            text="🗂️ Gestor de Cuarentena y Restauración",
            font=("Segoe UI", 15, "bold")
        ).pack(anchor="w")

        ttk.Label(
            container,
            text="Seleccione una sesión para devolver sus archivos a la ubicación original o liberar espacio purgándola.",
            font=("Segoe UI", 10)
        ).pack(anchor="w", pady=(2, 12))

        # 2.2 Directorio base explorado con opción de cambio y manifest manual
        dir_frame = ttk.Frame(container, style="Card.TFrame", padding=(12, 8))
        dir_frame.pack(fill="x", pady=(0, 12))

        ttk.Label(
            dir_frame,
            text="📁 Carpeta explorada:",
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=(0, 8))

        self.dir_lbl = ttk.Label(
            dir_frame,
            text=str(self.base_dir),
            font=("Segoe UI", 9)
        )
        self.dir_lbl.pack(side="left", fill="x", expand=True)

        manual_btn = ttk.Button(
            dir_frame,
            text="📄 Cargar manifest.json...",
            command=self._browse_manual_manifest
        )
        manual_btn.pack(side="right", padx=(8, 0))

        change_dir_btn = ttk.Button(
            dir_frame,
            text="📂 Cambiar carpeta...",
            command=self._change_search_dir
        )
        change_dir_btn.pack(side="right")

        # 2.3 Treeview de Sesiones (Tabla)
        table_frame = ttk.Frame(container)
        table_frame.pack(fill="both", expand=True, pady=(0, 10))

        columns = ("timestamp", "files", "bytes", "session")
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
            style="Data.Treeview",
            height=7
        )

        self.tree.heading("timestamp", text="Fecha y Hora")
        self.tree.heading("files", text="Archivos Aislados")
        self.tree.heading("bytes", text="Tamaño en Disco")
        self.tree.heading("session", text="Identificador de Sesión")

        self.tree.column("timestamp", width=180, anchor="center")
        self.tree.column("files", width=150, anchor="center")
        self.tree.column("bytes", width=130, anchor="e")
        self.tree.column("session", width=240, anchor="w")

        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll_y.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self._on_session_selected)

        # 2.4 Resumen Dinámico de Selección
        self.summary_card = ttk.Frame(container, style="Card.TFrame", padding=(12, 10))
        self.summary_card.pack(fill="x", pady=(0, 6))

        self.summary_lbl = ttk.Label(
            self.summary_card,
            text="ℹ️ Ninguna sesión seleccionada. Haga clic en una fila de la tabla.",
            font=("Segoe UI", 9, "bold")
        )
        self.summary_lbl.pack(anchor="w")

        # 2.5 Barra de Progreso
        self.prog_bar = ttk.Progressbar(container, mode="indeterminate")

    def _load_sessions(self):
        """Escanea localmente las carpetas _quarantine_* y carga los metadatos."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.selected_session = None
        self.restore_btn.configure(state="disabled")
        self.purge_btn.configure(state="disabled")

        self.sessions = find_quarantine_sessions(self.base_dir)

        if not self.sessions:
            self.purge_all_btn.configure(state="disabled")
            self.summary_lbl.configure(
                text="ℹ️ No se encontraron sesiones de cuarentena (_quarantine_*) en este directorio."
            )
            return

        self.purge_all_btn.configure(state="normal")

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

        # Seleccionar automáticamente la primera sesión para agilizar el flujo
        first_id = "0"
        if self.tree.exists(first_id):
            self.tree.selection_set(first_id)
            self.tree.focus(first_id)
            self._on_session_selected(None)
        else:
            self.summary_lbl.configure(
                text=f"✔ Se encontraron {len(self.sessions)} sesiones disponibles. Seleccione una para gestionar."
            )

    def _on_session_selected(self, event):
        selected = self.tree.selection()
        if not selected:
            self.selected_session = None
            self.restore_btn.configure(state="disabled")
            self.purge_btn.configure(state="disabled")
            self.summary_lbl.configure(text="ℹ️ Ninguna sesión seleccionada.")
            return

        idx = int(selected[0])
        self.selected_session = self.sessions[idx]

        s = self.selected_session
        self.summary_lbl.configure(
            text=f"✅ Sesión activa: {s['total_files']} archivos ({s['total_bytes_formatted']}) "
                 f"creada el {s['timestamp']}  —  Carpeta: {s['folder_name']}"
        )
        self.restore_btn.configure(state="normal")
        self.purge_btn.configure(state="normal")

    def _execute_purge(self):
        """Opción 1: Purgar definitivamente la carpeta de aislamiento de la sesión seleccionada."""
        if not self.selected_session:
            return

        s = self.selected_session
        confirm = messagebox.askyesno(
            "Confirmar Vaciado de Cuarentena (Purgar)",
            f"¿Desea eliminar definitivamente la sesión de cuarentena '{s['session_id']}'?\n\n"
            f"• Carpeta: {s['folder_name']}\n"
            f"• Archivos aislados: {s['total_files']}\n"
            f"• Espacio a liberar: {s['total_bytes_formatted']}\n\n"
            f"⚠️ ADVERTENCIA: Esta acción es IRREVERSIBLE. Se eliminará la carpeta de aislamiento y todos los archivos contenidos.",
            icon="warning",
            parent=self
        )
        if not confirm:
            return

        try:
            purge_quarantine_session(s["folder_path"])
            self.history_manager.record_event(
                action_type="PURGE",
                target_dir=self.base_dir,
                files_count=s["total_files"],
                bytes_count=s["total_bytes"]
            )
            messagebox.showinfo(
                "Cuarentena Purgada",
                f"La sesión '{s['session_id']}' fue eliminada permanentemente.",
                parent=self
            )
            self._load_sessions()
            if self.on_restore_success:
                self.on_restore_success()
        except Exception as e:
            messagebox.showerror("Error al Purgar", f"No se pudo purgar la sesión: {e}", parent=self)

    def _execute_purge_all(self):
        """Opción 1: Purgar todas las sesiones de cuarentena del directorio actual."""
        if not self.sessions:
            return

        total_f = sum(s.get("total_files", 0) for s in self.sessions)
        total_b = sum(s.get("total_bytes", 0) for s in self.sessions)

        confirm = messagebox.askyesno(
            "Confirmar Vaciado Completo de Cuarentenas",
            f"¿Desea eliminar definitivamente TODAS las {len(self.sessions)} sesiones de cuarentena encontradas en este directorio?\n\n"
            f"⚠️ ADVERTENCIA: Esta acción es IRREVERSIBLE y destruirá permanentemente todos los archivos aislados.",
            icon="warning",
            parent=self
        )
        if not confirm:
            return

        try:
            purged = purge_all_quarantine_sessions(self.base_dir)
            if purged > 0:
                self.history_manager.record_event(
                    action_type="PURGE",
                    target_dir=self.base_dir,
                    files_count=total_f,
                    bytes_count=total_b
                )
            messagebox.showinfo(
                "Vaciado Completo",
                f"Se purgaron {purged} sesiones de cuarentena satisfactoriamente.",
                parent=self
            )
            self._load_sessions()
            if self.on_restore_success:
                self.on_restore_success()
        except Exception as e:
            messagebox.showerror("Error al Purgar", f"Ocurrió un error purgando sesiones: {e}", parent=self)

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
            f"• Volumen de datos: {s['total_bytes_formatted']}\n\n"
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

        if res.total_restored > 0:
            self.history_manager.record_event(
                action_type="RESTORE",
                target_dir=self.base_dir,
                files_count=res.total_restored,
                bytes_count=res.total_bytes_restored
            )

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
        self.root.title("DataCleaner — Auditoría Inteligente y Organización de Archivos (SHA-256)")
        self.root.geometry("1160x820")
        self.root.minsize(920, 640)

        # Estado del modelo
        self.current_theme = "dark"
        self.current_base_dir: Path | None = None
        self.last_duplicates: dict[str, list[Path]] = {}
        self.last_summary: ScanSummary | None = None
        self.last_report: dict[str, Any] | None = None
        self.all_table_rows: list[dict[str, Any]] = []
        self.is_processing = False
        self.is_advanced_open = False
        self.validation_state = "idle"  # "idle", "valid", "warning", "error"
        self.history_manager = CleaningHistoryManager()
        self.unit_preference = "AUTO"  # "AUTO", "GB", "MB", "KB"

        # 1. Inyección de Tema Sun Valley (Fluent Design Windows 11)
        self._apply_sun_valley_theme()

        # 2. Construcción de la interfaz
        self._build_interface()
        self._bind_shortcuts()
        self._on_action_mode_changed()
        self._apply_theme_colors_to_widgets()
        self._refresh_history_view()
        apply_windows_titlebar_theme(self.root, self.current_theme == "dark")

        if initial_dir:
            self._set_directory_path(str(initial_dir))
        else:
            self._refresh_quarantine_badge()

    def _bind_shortcuts(self):
        """Atajos de teclado globales para accesibilidad sin ratón."""
        self.root.bind("<F5>", lambda e: self._start_scan_thread())
        self.root.bind("<Control-o>", lambda e: self._browse_directory())
        self.root.bind("<Control-O>", lambda e: self._browse_directory())
        self.root.bind("<Control-g>", lambda e: self._open_restore_modal())
        self.root.bind("<Control-G>", lambda e: self._open_restore_modal())
        self.root.bind("<Control-e>", lambda e: self._export_json_report())
        self.root.bind("<Control-E>", lambda e: self._export_json_report())
        self.root.bind("<Control-t>", lambda e: self._toggle_theme())
        self.root.bind("<Control-T>", lambda e: self._toggle_theme())
        self.root.bind("<Control-f>", lambda e: self._focus_search_entry())
        self.root.bind("<Control-F>", lambda e: self._focus_search_entry())

    def _focus_search_entry(self):
        if hasattr(self, "search_entry"):
            self.notebook.select(0)
            self.search_entry.focus_set()

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
        """Configuración de tipografías y colores de alto contraste WCAG 2.1 AA."""
        style = ttk.Style(self.root)
        is_dark = (self.current_theme == "dark")

        style.configure("HeaderTitle.TLabel", font=("Segoe UI", 19, "bold"))
        style.configure(
            "HeaderBadge.TLabel",
            font=("Segoe UI", 9, "bold"),
            foreground="#58A6FF" if is_dark else "#0969DA"
        )
        style.configure(
            "HeaderSubtitle.TLabel",
            font=("Segoe UI", 10),
            foreground="#A0AAB4" if is_dark else "#57606A"
        )
        style.configure(
            "CardTitle.TLabel",
            font=("Segoe UI", 9, "bold"),
            foreground="#9CA3AF" if is_dark else "#57606A"
        )
        style.configure("CardValue.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure(
            "AccentValue.TLabel",
            font=("Segoe UI", 20, "bold"),
            foreground="#4CC2FF" if is_dark else "#005FB8"
        )
        style.configure(
            "WarnValue.TLabel",
            font=("Segoe UI", 20, "bold"),
            foreground="#F0883E" if is_dark else "#BC4C00"
        )
        style.configure(
            "CardCaption.TLabel",
            font=("Segoe UI", 8),
            foreground="#768390" if is_dark else "#6E7781"
        )

        style.configure("Data.Treeview", rowheight=30, font=("Segoe UI", 9))
        style.configure("Data.Treeview.Heading", font=("Segoe UI", 9, "bold"))

        # Contraste garantizado en botones tanto en tema oscuro como en tema claro
        if is_dark:
            style.configure(
                "TButton",
                foreground="#FFFFFF",
                font=("Segoe UI", 9, "normal"),
                padding=(12, 6)
            )
            style.map(
                "TButton",
                foreground=[
                    ("disabled", "#787878"),
                    ("pressed", "#FFFFFF"),
                    ("active", "#FFFFFF")
                ]
            )
            style.configure(
                "Accent.TButton",
                foreground="#000000",
                font=("Segoe UI", 9, "bold"),
                padding=(14, 6)
            )
            style.map(
                "Accent.TButton",
                foreground=[
                    ("disabled", "#8A8A8A"),
                    ("pressed", "#000000"),
                    ("active", "#000000")
                ]
            )
        else:
            style.configure(
                "TButton",
                foreground="#1A1A1A",
                font=("Segoe UI", 9, "normal"),
                padding=(12, 6)
            )
            style.map(
                "TButton",
                foreground=[
                    ("disabled", "#767676"),
                    ("pressed", "#000000"),
                    ("active", "#000000")
                ]
            )
            style.configure(
                "Accent.TButton",
                foreground="#FFFFFF",
                font=("Segoe UI", 9, "bold"),
                padding=(14, 6)
            )
            style.map(
                "Accent.TButton",
                foreground=[
                    ("disabled", "#5A5A5A"),
                    ("pressed", "#FFFFFF"),
                    ("active", "#FFFFFF")
                ]
            )

    def _toggle_theme(self):
        """Conmutación centralizada de tema oscuro / claro."""
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        if HAS_SV_TTK:
            sv_ttk.set_theme(self.current_theme)
        self._configure_custom_styles()
        self._apply_theme_colors_to_widgets()
        apply_windows_titlebar_theme(self.root, self.current_theme == "dark")

    def _apply_theme_colors_to_widgets(self):
        """Actualiza colores dependientes del tema en widgets personalizados."""
        is_dark = (self.current_theme == "dark")
        if hasattr(self, "theme_btn"):
            self.theme_btn.configure(
                text="☀️ Modo Claro" if is_dark else "🌙 Modo Oscuro"
            )
        if hasattr(self, "log_text"):
            self.log_text.configure(
                bg="#14171A" if is_dark else "#F6F8FA",
                fg="#E6EDF3" if is_dark else "#1F2328",
                insertbackground="#FFFFFF" if is_dark else "#000000",
                selectbackground="#1F6FEB" if is_dark else "#0969DA",
                selectforeground="#FFFFFF"
            )
        if hasattr(self, "lifetime_badge_lbl"):
            self.lifetime_badge_lbl.configure(
                foreground="#3FB950" if is_dark else "#1A7F37"
            )
        self._update_validation_label_color()
        self._update_tag_colors()

    def _update_validation_label_color(self):
        if not hasattr(self, "validation_label"):
            return
        is_dark = (self.current_theme == "dark")
        color_map = {
            "idle": "#8B949E" if is_dark else "#57606A",
            "valid": "#3FB950" if is_dark else "#1A7F37",
            "warning": "#D29922" if is_dark else "#9A6700",
            "error": "#F85149" if is_dark else "#CF222E",
        }
        fg_color = color_map.get(self.validation_state, color_map["idle"])
        self.validation_label.configure(foreground=fg_color)

    def _build_interface(self):
        self.main_frame = ttk.Frame(self.root, padding=(22, 16))
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

        title_row = ttk.Frame(text_frame)
        title_row.pack(anchor="w")

        ttk.Label(
            title_row,
            text="🛡️ DataCleaner",
            style="HeaderTitle.TLabel"
        ).pack(side="left", padx=(0, 12))

        ttk.Label(
            title_row,
            text="● Motor SHA-256 · Política de Cero Pérdida de Datos",
            style="HeaderBadge.TLabel"
        ).pack(side="left", pady=(4, 0), padx=(0, 12))

        self.lifetime_badge_lbl = ttk.Label(
            title_row,
            text="🏆 Memoria Histórica Recuperada: 0 B",
            font=("Segoe UI", 9, "bold")
        )
        self.lifetime_badge_lbl.pack(side="left", pady=(4, 0))

        ttk.Label(
            text_frame,
            text="Paso 1: Elija una carpeta   ›   Paso 2: Inicie la simulación (F5)   ›   Paso 3: Aísle o limpie duplicados con seguridad",
            style="HeaderSubtitle.TLabel"
        ).pack(anchor="w", pady=(3, 0))

        self.theme_btn = ttk.Button(
            header_frame,
            text="☀️ Modo Claro",
            command=self._toggle_theme
        )
        self.theme_btn.pack(side="right", anchor="ne")

    def _build_selection_card(self):
        self.card_selection = ttk.Frame(self.main_frame, style="Card.TFrame", padding=(16, 14))
        self.card_selection.pack(fill="x", pady=(0, 12))

        # Fila 1: Entrada de ruta y botón Examinar
        row_browse = ttk.Frame(self.card_selection)
        row_browse.pack(fill="x", pady=(0, 8))

        ttk.Label(
            row_browse,
            text="📁 Carpeta a auditar:",
            font=("Segoe UI", 10, "bold")
        ).pack(side="left", padx=(0, 10))

        self.path_entry = ttk.Entry(row_browse, font=("Segoe UI", 10))
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.path_entry.bind("<KeyRelease>", self._on_path_key_release)
        self.path_entry.bind("<Return>", lambda e: self._start_scan_thread())

        self.clear_path_btn = ttk.Button(
            row_browse,
            text="✕",
            command=self._clear_directory_path,
            width=3
        )
        self.clear_path_btn.pack(side="left", padx=(0, 6))

        browse_btn = ttk.Button(
            row_browse,
            text="📂 Examinar... (Ctrl+O)",
            command=self._browse_directory
        )
        browse_btn.pack(side="left")

        # Fila 2: Accesos rápidos a carpetas frecuentes del usuario
        row_quick = ttk.Frame(self.card_selection)
        row_quick.pack(fill="x", pady=(0, 8))

        ttk.Label(
            row_quick,
            text="Accesos rápidos:",
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=(0, 8))

        user_home = Path.home()
        quick_folders = [
            ("📥 Descargas", user_home / "Downloads"),
            ("📄 Documentos", user_home / "Documents"),
            ("🖼️ Imágenes", user_home / "Pictures"),
            ("🖥️ Escritorio", user_home / "Desktop"),
        ]
        for label, folder_path in quick_folders:
            if folder_path.exists():
                btn = ttk.Button(
                    row_quick,
                    text=label,
                    command=lambda p=folder_path: self._set_directory_path(str(p))
                )
                btn.pack(side="left", padx=(0, 6))

        # Botón de opciones avanzadas alineado a la derecha de la barra de accesos rápidos
        self.adv_btn = ttk.Button(
            row_quick,
            text="⚙️ Opciones avanzadas ▾",
            command=self._toggle_advanced_options
        )
        self.adv_btn.pack(side="right")

        # Fila 3: Estado de validación semántico con color de alto contraste
        self.validation_label = ttk.Label(
            self.card_selection,
            text="ℹ️ Seleccione una carpeta o utilice un acceso rápido para comenzar.",
            font=("Segoe UI", 9, "bold")
        )
        self.validation_label.pack(anchor="w")

        # Panel desplegable de opciones avanzadas
        self.advanced_frame = ttk.Frame(self.card_selection, padding=(4, 10, 4, 2))

        sep = ttk.Separator(self.advanced_frame, orient="horizontal")
        sep.pack(fill="x", pady=(0, 10))

        row_adv = ttk.Frame(self.advanced_frame)
        row_adv.pack(fill="x")

        ttk.Label(
            row_adv,
            text="🎯 Regla de Conservación (KEEP):",
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=(0, 8))

        self.rule_combobox = ttk.Combobox(
            row_adv,
            values=list(RULE_OPTIONS.keys()),
            state="readonly",
            width=50,
            font=("Segoe UI", 9)
        )
        self.rule_combobox.current(0)
        self.rule_combobox.pack(side="left", padx=(0, 16))

        default_workers = get_safe_worker_count()
        ttk.Label(
            row_adv,
            text=f"⚡ Hilos I/O: {default_workers} (Óptimo para su CPU)",
            font=("Segoe UI", 9)
        ).pack(side="left")

        # Fila 2 de opciones avanzadas: Modos Directos de Eliminación (Opciones 2 y 3)
        row_opts = ttk.Frame(self.advanced_frame)
        row_opts.pack(fill="x", pady=(10, 0))

        ttk.Label(
            row_opts,
            text="🛡️ Modo de Acción:",
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=(0, 10))

        self.direct_delete_var = tk.BooleanVar(value=False)
        self.use_trash_var = tk.BooleanVar(value=True)

        self.direct_delete_check = ttk.Checkbutton(
            row_opts,
            text="Eliminar directamente sin pasar por cuarentena",
            variable=self.direct_delete_var,
            command=self._on_action_mode_changed
        )
        self.direct_delete_check.pack(side="left", padx=(0, 16))

        trash_label = "Usar Papelera de Reciclaje de Windows (send2trash - Recomendado)" if HAS_SEND2TRASH else "Usar Papelera de Windows"
        self.use_trash_check = ttk.Checkbutton(
            row_opts,
            text=trash_label,
            variable=self.use_trash_var,
            command=self._on_action_mode_changed
        )
        self.use_trash_check.pack(side="left")

    def _on_action_mode_changed(self):
        """Actualiza la interfaz según las opciones de cuarentena, papelera o borrado directo."""
        if not self.direct_delete_var.get():
            self.use_trash_check.configure(state="disabled")
            self.quarantine_btn.configure(text="📦 Aislar en Cuarentena")
        else:
            self.use_trash_check.configure(state="normal")
            if self.use_trash_var.get():
                self.quarantine_btn.configure(text="🗑️ Enviar a Papelera de Windows")
            else:
                self.quarantine_btn.configure(text="⚠️ Eliminar Permanentemente (Irreversible)")

    def _build_action_bar(self):
        action_bar = ttk.Frame(self.main_frame)
        action_bar.pack(fill="x", pady=(0, 12))

        # Grupo Izquierdo: Flujo Primario de Auditoría
        self.scan_btn = ttk.Button(
            action_bar,
            text="🔍 Iniciar Simulación (F5)",
            command=self._start_scan_thread,
            state="disabled"
        )
        self.scan_btn.pack(side="left", padx=(0, 8))

        self.quarantine_btn = ttk.Button(
            action_bar,
            text="📦 Aislar en Cuarentena",
            command=self._execute_quarantine,
            state="disabled"
        )
        self.quarantine_btn.pack(side="left", padx=(0, 16))

        # Grupo Derecho: Exportación y Gestión de Sesiones de Cuarentena
        self.export_btn = ttk.Button(
            action_bar,
            text="💾 Exportar JSON",
            command=self._export_json_report,
            state="disabled"
        )
        self.export_btn.pack(side="right")

        self.purge_bar_btn = ttk.Button(
            action_bar,
            text="🗑️ Vaciar Cuarentena",
            command=self._open_restore_modal
        )
        self.purge_bar_btn.pack(side="right", padx=(0, 8))

        self.restore_btn = ttk.Button(
            action_bar,
            text="🔄 Restaurar / Sesiones (0)",
            command=self._open_restore_modal
        )
        self.restore_btn.pack(side="right", padx=(0, 8))

    def _refresh_quarantine_badge(self):
        """Actualiza el contador de sesiones de cuarentena disponibles en la barra de acciones."""
        search_dir = self.current_base_dir or Path.cwd()
        try:
            sessions = find_quarantine_sessions(search_dir)
            count = len(sessions)
        except Exception:
            count = 0

        if hasattr(self, "restore_btn"):
            self.restore_btn.configure(text=f"🔄 Restaurar / Sesiones ({count})")

    def _build_dashboard_cards(self):
        cards_frame = ttk.Frame(self.main_frame)
        cards_frame.pack(fill="x", pady=(0, 12))

        self.card_files, self.cap_files = self._create_card(
            cards_frame,
            "📄 ARCHIVOS ANALIZADOS",
            "0",
            "Volumen total: 0 B"
        )
        self.card_groups, self.cap_groups = self._create_card(
            cards_frame,
            "🗂️ GRUPOS DUPLICADOS",
            "0",
            "Colisiones exactas SHA-256"
        )
        self.card_redundant, self.cap_redundant = self._create_card(
            cards_frame,
            "📋 COPIAS REDUNDANTES",
            "0",
            "Candidatos para aislamiento",
            value_style="WarnValue.TLabel"
        )
        self.card_recoverable, self.cap_recoverable = self._create_card(
            cards_frame,
            "✨ ESPACIO RECUPERABLE",
            "0 B",
            "Ahorro potencial en disco",
            value_style="AccentValue.TLabel"
        )

    def _create_card(
        self,
        parent: ttk.Frame,
        title: str,
        initial_val: str,
        caption: str,
        value_style: str = "CardValue.TLabel"
    ) -> tuple[ttk.Label, ttk.Label]:
        card = ttk.Frame(parent, style="Card.TFrame", padding=(14, 10))
        card.pack(side="left", fill="both", expand=True, padx=4)

        ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="w")
        val_lbl = ttk.Label(
            card,
            text=initial_val,
            style=value_style
        )
        val_lbl.pack(anchor="w", pady=(4, 2))

        cap_lbl = ttk.Label(
            card,
            text=caption,
            style="CardCaption.TLabel"
        )
        cap_lbl.pack(anchor="w")
        return val_lbl, cap_lbl

    def _build_progress_area(self):
        prog_frame = ttk.Frame(self.main_frame)
        prog_frame.pack(fill="x", pady=(0, 10))

        status_row = ttk.Frame(prog_frame)
        status_row.pack(fill="x", pady=(0, 4))

        self.status_label = ttk.Label(
            status_row,
            text="Listo para iniciar auditoría. Ningún archivo será modificado durante la simulación.",
            font=("Segoe UI", 9)
        )
        self.status_label.pack(side="left")

        self.percent_label = ttk.Label(
            status_row,
            text="",
            font=("Segoe UI", 9, "bold")
        )
        self.percent_label.pack(side="right")

        self.progress_bar = ttk.Progressbar(prog_frame, mode="determinate")
        self.progress_bar.pack(fill="x")

    def _build_notebook_tabs(self):
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill="both", expand=True)

        tab_dups = ttk.Frame(self.notebook, padding=8)
        tab_history = ttk.Frame(self.notebook, padding=8)
        tab_log = ttk.Frame(self.notebook, padding=8)

        self.notebook.add(tab_dups, text=" 📊 Duplicados Encontrados ")
        self.notebook.add(tab_history, text=" 🏆 Historial y Memoria Recuperada ")
        self.notebook.add(tab_log, text=" 📝 Bitácora de Auditoría ")

        self._build_history_tab(tab_history)

        # Barra de herramientas de filtrado y acciones rápidas de tabla
        filter_bar = ttk.Frame(tab_dups)
        filter_bar.pack(fill="x", pady=(0, 8))

        ttk.Label(
            filter_bar,
            text="🔎 Filtrar:",
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=(0, 6))

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._apply_table_filter())
        self.search_entry = ttk.Entry(filter_bar, textvariable=self.search_var, width=32, font=("Segoe UI", 9))
        self.search_entry.pack(side="left", padx=(0, 10))

        ttk.Label(
            filter_bar,
            text="Vista:",
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=(0, 6))

        self.filter_mode_var = tk.StringVar(value="Todos")
        self.filter_combo = ttk.Combobox(
            filter_bar,
            textvariable=self.filter_mode_var,
            values=["Todos", "Solo Conservar (KEEP)", "Solo Redundantes (QUARANTINE)"],
            state="readonly",
            width=28,
            font=("Segoe UI", 9)
        )
        self.filter_combo.pack(side="left", padx=(0, 10))
        self.filter_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_table_filter())

        open_loc_btn = ttk.Button(
            filter_bar,
            text="📂 Mostrar en Explorador",
            command=self._open_selected_in_explorer
        )
        open_loc_btn.pack(side="right")

        copy_path_btn = ttk.Button(
            filter_bar,
            text="📋 Copiar Ruta",
            command=self._copy_selected_path
        )
        copy_path_btn.pack(side="right", padx=(0, 6))

        # Tabla Treeview
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
        self.tree.heading("action", text="Estado / Acción")
        self.tree.heading("size", text="Tamaño")
        self.tree.heading("hash_short", text="SHA-256")
        self.tree.heading("path", text="Ruta del Archivo (Doble clic para abrir carpeta)")

        self.tree.column("group", width=70, anchor="center")
        self.tree.column("action", width=155, anchor="center")
        self.tree.column("size", width=105, anchor="e")
        self.tree.column("hash_short", width=110, anchor="center")
        self.tree.column("path", width=600, anchor="w")

        scroll_y = ttk.Scrollbar(table_container, orient="vertical", command=self.tree.yview)
        scroll_x = ttk.Scrollbar(table_container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        self.tree.pack(side="left", fill="both", expand=True)

        # Menú contextual (clic derecho) y doble clic en tabla
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="📂 Mostrar en Explorador de Windows", command=self._open_selected_in_explorer)
        self.context_menu.add_command(label="📄 Abrir archivo", command=self._open_selected_file)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📋 Copiar ruta completa", command=self._copy_selected_path)
        self.context_menu.add_command(label="🔑 Copiar Hash SHA-256", command=self._copy_selected_hash)

        self.tree.bind("<Double-1>", lambda e: self._open_selected_in_explorer())
        self.tree.bind("<Button-3>", self._show_context_menu)

        self._update_tag_colors()

        # Pestaña Bitácora
        log_toolbar = ttk.Frame(tab_log)
        log_toolbar.pack(fill="x", pady=(0, 6))

        ttk.Label(
            log_toolbar,
            text="Registro detallado de operaciones y auditoría SHA-256",
            font=("Segoe UI", 9, "bold")
        ).pack(side="left")

        clear_log_btn = ttk.Button(
            log_toolbar,
            text="🧹 Limpiar Bitácora",
            command=lambda: self.log_text.delete("1.0", tk.END)
        )
        clear_log_btn.pack(side="right")

        self.log_text = ScrolledText(
            tab_log,
            wrap="word",
            font=("Consolas", 10),
            padx=12,
            pady=10,
            relief="flat",
            borderwidth=1
        )
        self.log_text.pack(fill="both", expand=True)

    def _build_history_tab(self, tab_history: ttk.Frame):
        """
        Construye el panel de Historial de Limpieza y Memoria Recuperada:
        - 3 Tarjetas KPI acumulativas con conversión dinámica (B / KB / MB / GB / TB) y equivalencias.
        - Selector de unidad preferida (Automático, GB, MB, KB) + Exportar / Reiniciar.
        - Tabla detallada de operaciones históricas (Cuarentena, Papelera, Eliminación Permanente, Purgado, Restauración).
        """
        hist_cards = ttk.Frame(tab_history)
        hist_cards.pack(fill="x", pady=(0, 10))

        self.hist_card_space, self.hist_cap_space = self._create_card(
            hist_cards,
            "💾 MEMORIA TOTAL RECUPERADA",
            "0 B",
            "Conversión: 0.00 MB  •  0.000 GB",
            value_style="AccentValue.TLabel"
        )
        self.hist_card_files, self.hist_cap_files = self._create_card(
            hist_cards,
            "🧹 REDUNDANCIAS ELIMINADAS",
            "0",
            "Copias duplicadas limpiadas en total",
            value_style="WarnValue.TLabel"
        )
        self.hist_card_ops, self.hist_cap_ops = self._create_card(
            hist_cards,
            "⚡ OPERACIONES E IMPACTO",
            "0 sesiones",
            "Purgado definitivo: 0 B",
            value_style="CardValue.TLabel"
        )

        # Barra de herramientas del historial (Selector de unidad + acciones)
        hist_toolbar = ttk.Frame(tab_history)
        hist_toolbar.pack(fill="x", pady=(0, 8))

        ttk.Label(
            hist_toolbar,
            text="📐 Unidad de visualización:",
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=(0, 8))

        self.unit_combo_var = tk.StringVar(value="Automático Inteligente (B → KB → MB → GB → TB)")
        self.unit_combo = ttk.Combobox(
            hist_toolbar,
            textvariable=self.unit_combo_var,
            values=[
                "Automático Inteligente (B → KB → MB → GB → TB)",
                "Forzar en Gigabytes (GB)",
                "Forzar en Megabytes (MB)",
                "Forzar en Kilobytes (KB)",
            ],
            state="readonly",
            width=42,
            font=("Segoe UI", 9)
        )
        self.unit_combo.pack(side="left", padx=(0, 12))
        self.unit_combo.bind("<<ComboboxSelected>>", self._on_unit_preference_changed)

        clear_hist_btn = ttk.Button(
            hist_toolbar,
            text="🗑️ Reiniciar Historial",
            command=self._clear_history_prompt
        )
        clear_hist_btn.pack(side="right")

        export_hist_btn = ttk.Button(
            hist_toolbar,
            text="💾 Exportar Historial JSON",
            command=self._export_history_json
        )
        export_hist_btn.pack(side="right", padx=(0, 8))

        # Tabla Treeview del Historial
        hist_table_frame = ttk.Frame(tab_history)
        hist_table_frame.pack(fill="both", expand=True)

        hist_cols = ("timestamp", "action", "files", "space", "equiv", "folder")
        self.history_tree = ttk.Treeview(
            hist_table_frame,
            columns=hist_cols,
            show="headings",
            selectmode="browse",
            style="Data.Treeview"
        )

        self.history_tree.heading("timestamp", text="Fecha y Hora")
        self.history_tree.heading("action", text="Tipo de Operación")
        self.history_tree.heading("files", text="Redundancias")
        self.history_tree.heading("space", text="Memoria Recuperada")
        self.history_tree.heading("equiv", text="Equivalencia Exacta (MB ↔ GB)")
        self.history_tree.heading("folder", text="Carpeta / Detalle")

        self.history_tree.column("timestamp", width=150, anchor="center")
        self.history_tree.column("action", width=190, anchor="center")
        self.history_tree.column("files", width=115, anchor="center")
        self.history_tree.column("space", width=140, anchor="e")
        self.history_tree.column("equiv", width=220, anchor="center")
        self.history_tree.column("folder", width=360, anchor="w")

        h_scroll_y = ttk.Scrollbar(hist_table_frame, orient="vertical", command=self.history_tree.yview)
        h_scroll_x = ttk.Scrollbar(hist_table_frame, orient="horizontal", command=self.history_tree.xview)
        self.history_tree.configure(yscrollcommand=h_scroll_y.set, xscrollcommand=h_scroll_x.set)

        h_scroll_y.pack(side="right", fill="y")
        h_scroll_x.pack(side="bottom", fill="x")
        self.history_tree.pack(side="left", fill="both", expand=True)

    def _on_unit_preference_changed(self, event=None):
        sel = self.unit_combo_var.get()
        if "Gigabytes" in sel:
            self.unit_preference = "GB"
        elif "Megabytes" in sel:
            self.unit_preference = "MB"
        elif "Kilobytes" in sel:
            self.unit_preference = "KB"
        else:
            self.unit_preference = "AUTO"
        self._refresh_history_view()

    def _refresh_history_view(self):
        """Actualiza las tarjetas de memoria recuperada, insignia superior y tabla de historial."""
        summary = self.history_manager.get_summary()
        total_b = summary.total_bytes_recovered
        unit_pref = getattr(self, "unit_preference", "AUTO")

        # Formateo principal según preferencia (AUTO escala a GB automáticamente cuando >= 1000 MB)
        primary_space_str = format_bytes_auto(total_b, target_unit=unit_pref)
        mb_val = total_b / (1024 ** 2)
        gb_val = total_b / (1024 ** 3)

        if hasattr(self, "lifetime_badge_lbl"):
            self.lifetime_badge_lbl.configure(
                text=f"🏆 Memoria Histórica Recuperada: {format_bytes_with_equivalence(total_b)}"
            )

        if hasattr(self, "hist_card_space"):
            self.hist_card_space.configure(text=primary_space_str)
            self.hist_cap_space.configure(
                text=f"Equivalencia: {mb_val:,.2f} MB  ↔  {gb_val:,.3f} GB"
            )
            self.hist_card_files.configure(text=f"{summary.total_files_cleaned:,}")
            self.hist_cap_files.configure(
                text="Copias duplicadas limpiadas en total"
            )
            self.hist_card_ops.configure(text=f"{summary.total_operations:,} sesiones")
            purged_str = format_bytes_auto(summary.total_bytes_purged, target_unit=unit_pref)
            self.hist_cap_ops.configure(
                text=f"Destruido/Purgado definitivo: {purged_str}"
            )

        if hasattr(self, "history_tree"):
            for item in self.history_tree.get_children():
                self.history_tree.delete(item)

            action_labels = {
                "QUARANTINE": ("📦 Aislado en Cuarentena", "hist_clean"),
                "TRASH": ("🗑️ Enviado a Papelera", "hist_clean"),
                "PERMANENT": ("🔥 Eliminación Permanente", "hist_purge"),
                "PURGE": ("🧹 Cuarentena Purgada", "hist_purge"),
                "RESTORE": ("🔄 Sesión Restaurada", "hist_restore"),
            }

            for entry in self.history_manager.get_entries():
                act_text, tag = action_labels.get(entry.action_type, (entry.action_type, "hist_clean"))
                sign = "-" if entry.action_type == "RESTORE" else "+"
                space_col = f"{sign}{format_bytes_auto(entry.bytes_affected, target_unit=unit_pref)}"
                e_mb = entry.bytes_affected / (1024 ** 2)
                e_gb = entry.bytes_affected / (1024 ** 3)
                equiv_col = f"{e_mb:,.2f} MB  |  {e_gb:,.3f} GB"
                folder_detail = entry.target_dir if not entry.details else f"{entry.target_dir} ({entry.details})"

                self.history_tree.insert(
                    "",
                    tk.END,
                    values=(
                        entry.timestamp,
                        act_text,
                        f"{entry.files_count:,} archivos",
                        space_col,
                        equiv_col,
                        folder_detail,
                    ),
                    tags=(tag,)
                )

    def _export_history_json(self):
        entries = self.history_manager.get_entries()
        if not entries:
            messagebox.showinfo("Historial Vacío", "Aún no hay operaciones registradas en el historial para exportar.")
            return

        save_path = filedialog.asksaveasfilename(
            title="Exportar Historial de Limpieza y Memoria Recuperada",
            defaultextension=".json",
            initialfile="datacleaner_historial_memoria.json",
            filetypes=[("Archivos JSON", "*.json")]
        )
        if save_path:
            summary = self.history_manager.get_summary()
            payload = {
                "summary": {
                    "total_operations": summary.total_operations,
                    "total_files_cleaned": summary.total_files_cleaned,
                    "total_bytes_recovered": summary.total_bytes_recovered,
                    "total_recovered_formatted": format_bytes_with_equivalence(summary.total_bytes_recovered),
                    "total_megabytes": round(summary.total_bytes_recovered / (1024 ** 2), 3),
                    "total_gigabytes": round(summary.total_bytes_recovered / (1024 ** 3), 4),
                },
                "entries": [e.to_dict() for e in entries],
            }
            Path(save_path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            messagebox.showinfo("Historial Exportado", f"El historial completo se exportó en:\n{save_path}")

    def _clear_history_prompt(self):
        if not self.history_manager.get_entries():
            return
        resp = messagebox.askyesno(
            "Reiniciar Historial de Memoria",
            "¿Desea poner en cero el contador histórico y borrar el registro de sesiones pasadas?\n\n"
            "(Esto solo limpia las estadísticas del historial; no afecta ningún archivo en disco).",
            icon="warning"
        )
        if resp:
            self.history_manager.clear_history()
            self._refresh_history_view()
            self.status_label.configure(text="🧹 Historial de limpieza y memoria recuperada reiniciado.")

    def _get_selected_row_values(self) -> tuple | None:
        selected = self.tree.selection()
        if not selected:
            return None
        return self.tree.item(selected[0], "values")

    def _show_context_menu(self, event):
        row_id = self.tree.identify_row(event.y)
        if row_id:
            self.tree.selection_set(row_id)
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def _open_selected_in_explorer(self):
        vals = self._get_selected_row_values()
        if not vals or len(vals) < 5:
            return
        file_path = Path(vals[4])
        if not file_path.exists():
            messagebox.showwarning("Archivo no encontrado", f"El archivo ya no se encuentra en:\n{file_path}")
            return
        try:
            if sys.platform == "win32":
                subprocess.Popen(["explorer", f"/select,{os.path.normpath(str(file_path))}"])
            else:
                subprocess.Popen(["xdg-open", str(file_path.parent)])
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el explorador: {e}")

    def _open_selected_file(self):
        vals = self._get_selected_row_values()
        if not vals or len(vals) < 5:
            return
        file_path = Path(vals[4])
        if file_path.exists() and sys.platform == "win32":
            try:
                os.startfile(str(file_path))
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo abrir el archivo: {e}")

    def _copy_selected_path(self):
        vals = self._get_selected_row_values()
        if not vals or len(vals) < 5:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(str(vals[4]))
        self.status_label.configure(text=f"📋 Ruta copiada al portapapeles: {vals[4]}")

    def _copy_selected_hash(self):
        vals = self._get_selected_row_values()
        if not vals or len(vals) < 4:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(str(vals[3]))
        self.status_label.configure(text=f"🔑 Hash copiado al portapapeles: {vals[3]}")

    def _update_tag_colors(self):
        is_dark = (self.current_theme == "dark")
        keep_bg = "#0D3528" if is_dark else "#DCFCE7"
        keep_fg = "#86EFAC" if is_dark else "#166534"
        quar_bg = "#3B1D0A" if is_dark else "#FEF3C7"
        quar_fg = "#FDE68A" if is_dark else "#92400E"
        purge_bg = "#3D1216" if is_dark else "#FEE2E2"
        purge_fg = "#FCA5A5" if is_dark else "#991B1B"

        self.tree.tag_configure("keep", background=keep_bg, foreground=keep_fg)
        self.tree.tag_configure("quarantine", background=quar_bg, foreground=quar_fg)

        if hasattr(self, "history_tree"):
            self.history_tree.tag_configure("hist_clean", background=keep_bg, foreground=keep_fg)
            self.history_tree.tag_configure("hist_purge", background=purge_bg, foreground=purge_fg)
            self.history_tree.tag_configure("hist_restore", background=quar_bg, foreground=quar_fg)

    def _toggle_advanced_options(self):
        if self.is_advanced_open:
            self.advanced_frame.pack_forget()
            self.adv_btn.configure(text="⚙️ Opciones avanzadas ▾")
            self.is_advanced_open = False
        else:
            self.advanced_frame.pack(fill="x", pady=(8, 0))
            self.adv_btn.configure(text="⚙️ Opciones avanzadas ▴")
            self.is_advanced_open = True

    def _set_directory_path(self, path_str: str):
        self.path_entry.delete(0, tk.END)
        self.path_entry.insert(0, path_str)
        self._validate_path_input(path_str)

    def _clear_directory_path(self):
        self.path_entry.delete(0, tk.END)
        self._validate_path_input("")

    def _on_path_key_release(self, event):
        path_str = self.path_entry.get().strip()
        self._validate_path_input(path_str)

    def _browse_directory(self):
        chosen = filedialog.askdirectory(title="Seleccionar carpeta a auditar")
        if chosen:
            self._set_directory_path(chosen)

    def _validate_path_input(self, path_str: str) -> bool:
        if not path_str:
            self.validation_state = "idle"
            self.validation_label.configure(
                text="ℹ️ Seleccione una carpeta o utilice un acceso rápido para comenzar."
            )
            self._update_validation_label_color()
            self.scan_btn.configure(state="disabled", style="TButton")
            self.current_base_dir = None
            self._refresh_quarantine_badge()
            return False

        try:
            validated = validate_target_path(path_str)
            self.validation_state = "valid"
            self.validation_label.configure(
                text=f"✅ Carpeta verificada y segura — Lista para iniciar simulación: {validated}"
            )
            self._update_validation_label_color()
            self.scan_btn.configure(state="normal", style="Accent.TButton")
            self.current_base_dir = validated
            self._refresh_quarantine_badge()
            return True
        except PermissionError as pe:
            self.validation_state = "error"
            self.validation_label.configure(
                text=f"⛔ Ruta bloqueada por protección del sistema: {pe}"
            )
            self._update_validation_label_color()
            self.scan_btn.configure(state="disabled", style="TButton")
            self.current_base_dir = None
            return False
        except FileNotFoundError:
            self.validation_state = "warning"
            self.validation_label.configure(
                text="⚠️ La carpeta especificada no existe en el almacenamiento."
            )
            self._update_validation_label_color()
            self.scan_btn.configure(state="disabled", style="TButton")
            self.current_base_dir = None
            return False
        except Exception as e:
            self.validation_state = "warning"
            self.validation_label.configure(
                text=f"⚠️ Ruta no válida: {e}"
            )
            self._update_validation_label_color()
            self.scan_btn.configure(state="disabled", style="TButton")
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
        self.quarantine_btn.configure(state="disabled", style="TButton")
        self.export_btn.configure(state="disabled")
        self.progress_bar["value"] = 0
        self.percent_label.configure(text="0%")
        self.status_label.configure(text="🔍 Escaneando árbol de directorios y agrupando por tamaño...")

        self.all_table_rows.clear()
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
        self.percent_label.configure(text=f"{percent}%")
        self.status_label.configure(text=text)

    def _on_scan_completed(self, duplicates: dict, summary: ScanSummary, report: dict):
        self.is_processing = False
        self.scan_btn.configure(state="normal", style="Accent.TButton")
        self.progress_bar["value"] = 100
        self.percent_label.configure(text="100%")
        self.last_duplicates = duplicates
        self.last_summary = summary
        self.last_report = report
        self._refresh_quarantine_badge()

        meta = report["metadata"]
        scanned_bytes = meta.get("total_bytes_scanned", 0)
        rec_bytes = meta.get("recoverable_bytes", 0)

        self.card_files.configure(text=f"{meta['total_files_scanned']:,}")
        self.cap_files.configure(text=f"Volumen: {format_bytes_with_equivalence(scanned_bytes)}")

        self.card_groups.configure(text=f"{meta['duplicate_groups']:,}")
        self.cap_groups.configure(text="Colisiones exactas SHA-256")

        self.card_redundant.configure(text=f"{meta['total_redundant_files']:,}")
        self.cap_redundant.configure(text="Archivos candidatos a limpiar")

        self.card_recoverable.configure(text=format_bytes_auto(rec_bytes))
        if rec_bytes > 0:
            rec_mb = rec_bytes / (1024 ** 2)
            rec_gb = rec_bytes / (1024 ** 3)
            self.cap_recoverable.configure(text=f"Equiv: {rec_mb:,.2f} MB  •  {rec_gb:,.3f} GB")
        else:
            self.cap_recoverable.configure(text="Ahorro potencial en disco")

        self.all_table_rows.clear()
        for idx, g in enumerate(report["groups"], start=1):
            short_hash = g["hash_sha256"][:8] + "…"
            f_size = g["file_size_formatted"]

            self.all_table_rows.append({
                "values": (f"#{idx}", "✔ CONSERVAR (KEEP)", f_size, short_hash, g["kept_file"]),
                "tag": "keep",
                "full_hash": g["hash_sha256"]
            })

            for q_file in g["quarantine_files"]:
                self.all_table_rows.append({
                    "values": (f"#{idx}", "📦 REDUNDANTE", f_size, short_hash, q_file),
                    "tag": "quarantine",
                    "full_hash": g["hash_sha256"]
                })

        self._apply_table_filter()

        if meta["total_redundant_files"] > 0:
            self.quarantine_btn.configure(state="normal", style="Accent.TButton")
            self._on_action_mode_changed()
            self.status_label.configure(
                text=f"✅ Simulación completada: {meta['total_redundant_files']} duplicados detectados "
                     f"({meta['recoverable_formatted']} recuperables)."
            )
        else:
            self.quarantine_btn.configure(state="disabled", style="TButton")
            self.status_label.configure(
                text="✨ Auditoría completada: No se encontraron archivos duplicados. Su carpeta está limpia."
            )

        self.export_btn.configure(state="normal")
        self._log(
            f"Auditoría finalizada. Grupos: {meta['duplicate_groups']} | "
            f"Redundantes: {meta['total_redundant_files']} | Recuperable: {meta['recoverable_formatted']}"
        )

    def _apply_table_filter(self):
        """Filtra en tiempo real las filas de la tabla según el texto buscado y el modo de vista."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        query = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""
        mode = self.filter_mode_var.get() if hasattr(self, "filter_mode_var") else "Todos"

        for row in self.all_table_rows:
            tag = row["tag"]
            vals = row["values"]

            if mode == "Solo Conservar (KEEP)" and tag != "keep":
                continue
            if mode == "Solo Redundantes (QUARANTINE)" and tag != "quarantine":
                continue

            if query:
                path_lower = str(vals[4]).lower()
                hash_lower = str(row.get("full_hash", "")).lower()
                group_lower = str(vals[0]).lower()
                if query not in path_lower and query not in hash_lower and query not in group_lower:
                    continue

            self.tree.insert("", tk.END, values=vals, tags=(tag,))

    def _execute_quarantine(self):
        if not self.last_report or not self.current_base_dir:
            return

        total_redundant = self.last_report["metadata"]["total_redundant_files"]
        rec_str = self.last_report["metadata"]["recoverable_formatted"]
        rule_key = self.rule_combobox.get()
        keep_rule = RULE_OPTIONS.get(rule_key, KeepRule.DEEPEST_THEN_NEWEST.value)
        plan = build_audit_plan(self.last_duplicates, keep_rule=keep_rule)

        # Opción 2 y 3: Eliminación directa (Papelera de Windows o Destrucción Permanente)
        if self.direct_delete_var.get():
            use_trash = self.use_trash_var.get()
            if use_trash:
                # Opción 3: Enviar a la Papelera de Reciclaje nativa de Windows (send2trash)
                resp = messagebox.askyesno(
                    "Confirmar Envío a Papelera de Reciclaje",
                    f"¿Desea enviar {total_redundant} archivos duplicados ({rec_str}) a la Papelera de Reciclaje de Windows?\n\n"
                    f"• Los archivos desaparecerán del directorio original liberando espacio de inmediato.\n"
                    f"• Podrá recuperarlos desde la Papelera de Windows si fuese necesario.",
                    icon="question"
                )
                if not resp:
                    return

                try:
                    res_del: DeleteResult = execute_deletion_plan(plan, use_trash=True)
                    self.history_manager.record_event(
                        action_type="TRASH",
                        target_dir=str(self.current_base_dir),
                        files_count=res_del.total_deleted,
                        bytes_affected=res_del.total_bytes_deleted,
                        details="Papelera de Reciclaje de Windows"
                    )
                    self._refresh_history_view()
                    self._log(f"\n✔ Papelera de Reciclaje: {res_del.total_deleted} archivos ({format_bytes_with_equivalence(res_del.total_bytes_deleted)}) enviados a la Papelera.")
                    if res_del.errors:
                        for err in res_del.errors:
                            self._log(f"  ⚠ {err}")

                    messagebox.showinfo(
                        "Operación Completada",
                        f"Se enviaron {res_del.total_deleted} archivos ({format_bytes_with_equivalence(res_del.total_bytes_deleted)}) a la Papelera de Reciclaje de Windows."
                    )
                    self.quarantine_btn.configure(state="disabled", style="TButton")
                    self._start_scan_thread()
                except Exception as e:
                    messagebox.showerror("Error al Enviar a Papelera", f"Ocurrió un error al procesar los archivos: {e}")
            else:
                # Opción 2: Eliminación permanente irreversible (Path.unlink / os.remove)
                resp = messagebox.askyesno(
                    "⚠️ Confirmar Eliminación Permanente (Irreversible)",
                    f"¿Está seguro de que desea ELIMINAR PERMANENTEMENTE {total_redundant} archivos duplicados ({rec_str})?\n\n"
                    f"⚠️ ADVERTENCIA CRÍTICA:\n"
                    f"• Los archivos NO serán enviados a cuarentena.\n"
                    f"• Los archivos NO irán a la Papelera de Reciclaje.\n"
                    f"• Serán borrados de raíz del disco (acción IRREVERSIBLE).\n\n"
                    f"¿Desea proceder con el borrado definitivo?",
                    icon="warning"
                )
                if not resp:
                    return

                try:
                    res_del: DeleteResult = execute_deletion_plan(plan, use_trash=False)
                    self.history_manager.record_event(
                        action_type="PERMANENT",
                        target_dir=str(self.current_base_dir),
                        files_count=res_del.total_deleted,
                        bytes_affected=res_del.total_bytes_deleted,
                        details="Borrado directo definitivo"
                    )
                    self._refresh_history_view()
                    self._log(f"\n✔ Eliminación permanente: {res_del.total_deleted} archivos ({format_bytes_with_equivalence(res_del.total_bytes_deleted)}) eliminados definitivamente del disco.")
                    if res_del.errors:
                        for err in res_del.errors:
                            self._log(f"  ⚠ {err}")

                    messagebox.showinfo(
                        "Eliminación Permanente Exitosa",
                        f"Se eliminaron permanentemente {res_del.total_deleted} archivos ({format_bytes_with_equivalence(res_del.total_bytes_deleted)}) del disco."
                    )
                    self.quarantine_btn.configure(state="disabled", style="TButton")
                    self._start_scan_thread()
                except Exception as e:
                    messagebox.showerror("Error en Eliminación Permanente", f"Ocurrió un error al eliminar los archivos: {e}")
            return

        # Opción Recomendada: Aislamiento No Destructivo en Cuarentena (Soft-Delete)
        resp = messagebox.askyesno(
            "Confirmar Cuarentena (Soft-Delete)",
            f"¿Desea mover {total_redundant} archivos duplicados ({rec_str}) a la carpeta de aislamiento?\n\n"
            f"Garantía de Cero Pérdida de Datos:\n"
            f"• Los archivos NO serán borrados permanentemente.\n"
            f"• Se trasladarán a una carpeta de cuarentena preservando su estructura.\n"
            f"• Podrá restaurarlos en cualquier momento o vaciar la cuarentena desde 'Vaciar Cuarentena'.",
            icon="question"
        )
        if not resp:
            return

        try:
            res: QuarantineResult = quarantine_redundant_files(self.current_base_dir, plan)
            self.history_manager.record_event(
                action_type="QUARANTINE",
                target_dir=str(self.current_base_dir),
                files_count=res.total_moved,
                bytes_affected=res.total_bytes_moved,
                details=f"Sesión {res.session_id}"
            )
            self._refresh_history_view()
            self._log(f"\n✔ Cuarentena completada: {res.total_moved} archivos trasladados a {res.quarantine_dir}")
            self._log(f"  Manifiesto generado: {res.manifest_path}")

            messagebox.showinfo(
                "Cuarentena Exitosa",
                f"Se trasladaron {res.total_moved} archivos ({format_bytes_with_equivalence(res.total_bytes_moved)}) a la carpeta de cuarentena.\n\n"
                f"Sesión: {res.session_id}\n"
                f"Ubicación:\n{res.quarantine_dir}\n\n"
                f"Puede restaurarlos en cualquier momento o vaciar la cuarentena desde el gestor de sesiones."
            )
            self.quarantine_btn.configure(state="disabled", style="TButton")
            self._refresh_quarantine_badge()
            self._start_scan_thread()
        except Exception as e:
            messagebox.showerror("Error en Cuarentena", f"Ocurrió un error al mover los archivos: {e}")

    def _open_restore_modal(self):
        """
        Fase 1 y 2: Invocación y apertura del Modal de Gestión de Cuarentena (RestoreModal).
        Explora las sesiones locales _quarantine_* del directorio actual.
        """
        search_dir = self.current_base_dir or Path.cwd()
        RestoreModal(
            parent=self.root,
            base_dir=search_dir,
            on_restore_success=self._on_modal_restore_success,
            is_dark=(self.current_theme == "dark"),
            history_manager=self.history_manager
        )

    def _on_modal_restore_success(self):
        """Callback invocado tras una restauración o purgado exitoso en el modal."""
        self._log("\n✔ Operación de gestión de cuarentena ejecutada desde el modal interactivo.")
        self._refresh_quarantine_badge()
        self._refresh_history_view()
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
