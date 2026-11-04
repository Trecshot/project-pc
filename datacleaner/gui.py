"""
Interfaz Gráfica de Usuario de Escritorio Moderna (CustomTkinter Desktop GUI)
DataCleaner GUI

Implementación moderna basada en CustomTkinter con diseño accesible (A11y),
modo oscuro/claro nativo, bordes redondeados, validación en línea de rutas,
aislamiento de tecnicismos y tarjetas de estadísticas de alto contraste (WCAG).
"""

import os
import threading
from pathlib import Path
from typing import Any
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from datacleaner.security import validate_target_path
from datacleaner.scanner import scan_directory_for_duplicates, ScanSummary
from datacleaner.rules import KeepRule
from datacleaner.hasher import get_safe_worker_count
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

# Configuración inicial de CustomTkinter
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

RULE_LABELS = {
    "Ruta más profunda y limpia, luego más reciente (Recomendado)": KeepRule.DEEPEST_THEN_NEWEST.value,
    "Ruta más profunda y limpia, luego más antigua": KeepRule.DEEPEST_THEN_OLDEST.value,
    "Ruta más superficial, luego más reciente": KeepRule.SHALLOWEST_THEN_NEWEST.value,
    "Solo el archivo más reciente": KeepRule.NEWEST_ONLY.value,
    "Solo el archivo más antiguo": KeepRule.OLDEST_ONLY.value,
}

class DataCleanerGUI:
    def __init__(self, root: ctk.CTk, initial_dir: str | None = None):
        self.root = root
        self.root.title("DataCleaner - Auditoría y Organización de Archivos")
        self.root.geometry("1120x780")
        self.root.minsize(880, 620)

        # Estado del modelo
        self.current_base_dir: Path | None = None
        self.last_duplicates: dict[str, list[Path]] = {}
        self.last_summary: ScanSummary | None = None
        self.last_report: dict[str, Any] | None = None
        self.is_processing = False
        self.is_advanced_open = False

        self._build_ui()
        self._setup_treeview_styles()

        if initial_dir:
            self.path_entry.insert(0, str(initial_dir))
            self._validate_path_input(str(initial_dir))

    def _build_ui(self):
        # Contenedor raíz con márgenes holgados (padx=20, pady=15)
        self.main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=20, pady=15)

        # 1. Cabecera con lenguaje guiado directo y selector de tema
        self._build_header()

        # 2. Panel de Selección y Validación en Línea
        self._build_selection_panel()

        # 3. Barra de Acciones y Call to Action (CTA)
        self._build_action_bar()

        # 4. Tarjetas de Estadísticas (Dashboard de Alto Contraste WCAG)
        self._build_metrics_cards()

        # 5. Barra de Progreso y Estado Operativo
        self._build_progress_bar()

        # 6. Área de Resultados (Pestañas para Duplicados y Bitácora)
        self._build_tabs_view()

    def _build_header(self):
        header_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 12))

        # Textos informativos con lenguaje instruccional directo
        info_subframe = ctk.CTkFrame(header_frame, fg_color="transparent")
        info_subframe.pack(side="left", fill="x", expand=True)

        title_lbl = ctk.CTkLabel(
            info_subframe,
            text="DataCleaner",
            font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold")
        )
        title_lbl.pack(anchor="w")

        # Lenguaje directo y claro para usuarios no técnicos
        subtitle_lbl = ctk.CTkLabel(
            info_subframe,
            text="1. Seleccione una carpeta.  2. Escanee en busca de duplicados.  Ningún archivo será borrado sin su confirmación.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=("gray35", "gray70")
        )
        subtitle_lbl.pack(anchor="w", pady=(2, 0))

        # Selector de Tema (Modo Claro / Oscuro / Sistema)
        theme_subframe = ctk.CTkFrame(header_frame, fg_color="transparent")
        theme_subframe.pack(side="right", anchor="e")

        theme_lbl = ctk.CTkLabel(theme_subframe, text="Tema:", font=ctk.CTkFont(family="Segoe UI", size=12))
        theme_lbl.pack(side="left", padx=(0, 6))

        self.theme_menu = ctk.CTkOptionMenu(
            theme_subframe,
            values=["Sistema", "Oscuro", "Claro"],
            command=self._change_theme,
            width=100,
            height=28,
            corner_radius=6
        )
        self.theme_menu.set("Sistema")
        self.theme_menu.pack(side="left")

    def _build_selection_panel(self):
        self.card_selection = ctk.CTkFrame(
            self.main_container,
            corner_radius=10,
            fg_color=("white", "#23272d"),
            border_width=1,
            border_color=("gray85", "#30363d")
        )
        self.card_selection.pack(fill="x", pady=(0, 12), padx=0)

        inner = ctk.CTkFrame(self.card_selection, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)

        # Fila 1: Campo de texto y botón examinar
        row_browse = ctk.CTkFrame(inner, fg_color="transparent")
        row_browse.pack(fill="x", pady=(0, 6))

        ctk.CTkLabel(
            row_browse,
            text="Carpeta a auditar:",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold")
        ).pack(side="left", padx=(0, 10))

        self.path_entry = ctk.CTkEntry(
            row_browse,
            placeholder_text="Haga clic en 'Examinar carpeta...' o ingrese la ruta del directorio",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            height=36,
            corner_radius=6
        )
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.path_entry.bind("<KeyRelease>", lambda event: self._on_entry_key(event))

        browse_btn = ctk.CTkButton(
            row_browse,
            text="Examinar carpeta...",
            command=self._browse_directory,
            width=160,
            height=36,
            corner_radius=6,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold")
        )
        browse_btn.pack(side="left")

        # Fila 2: Texto de validación en línea (Evita popups bloqueantes)
        self.validation_label = ctk.CTkLabel(
            inner,
            text="Por favor seleccione una carpeta para comenzar.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=("gray50", "gray65"),
            anchor="w"
        )
        self.validation_label.pack(fill="x", pady=(0, 6))

        # Fila 3: Toggle de Opciones Avanzadas (Aislamiento de tecnicismos)
        row_adv_toggle = ctk.CTkFrame(inner, fg_color="transparent")
        row_adv_toggle.pack(fill="x", pady=(2, 0))

        self.adv_btn = ctk.CTkButton(
            row_adv_toggle,
            text="⚙ Opciones avanzadas ▼",
            command=self._toggle_advanced_options,
            fg_color="transparent",
            hover_color=("gray90", "#2c313a"),
            text_color=("gray30", "gray80"),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            width=160,
            height=26,
            anchor="w"
        )
        self.adv_btn.pack(side="left")

        # Panel Colapsable de Opciones Avanzadas (Oculto por defecto)
        self.advanced_frame = ctk.CTkFrame(
            inner,
            fg_color=("gray95", "#1c2128"),
            corner_radius=8,
            border_width=1,
            border_color=("gray85", "#30363d")
        )

        adv_content = ctk.CTkFrame(self.advanced_frame, fg_color="transparent")
        adv_content.pack(fill="x", padx=12, pady=10)

        # Criterio de Conservación
        ctk.CTkLabel(
            adv_content,
            text="Criterio de Permanencia:",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold")
        ).pack(side="left", padx=(0, 8))

        self.rule_combobox = ctk.CTkOptionMenu(
            adv_content,
            values=list(RULE_LABELS.keys()),
            width=380,
            height=30,
            corner_radius=6
        )
        self.rule_combobox.set("Ruta más profunda y limpia, luego más reciente (Recomendado)")
        self.rule_combobox.pack(side="left", padx=(0, 20))

        # Hilos I/O automáticos
        default_workers = get_safe_worker_count()
        ctk.CTkLabel(
            adv_content,
            text=f"Hilos de Trabajo (I/O): {default_workers} (Automático según CPU)",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=("gray40", "gray70")
        ).pack(side="left")

    def _build_action_bar(self):
        action_bar = ctk.CTkFrame(self.main_container, fg_color="transparent")
        action_bar.pack(fill="x", pady=(0, 12))

        # CTA Principal: Destacado visualmente con color sólido
        self.scan_btn = ctk.CTkButton(
            action_bar,
            text="🔍 Iniciar Simulación",
            command=self._start_scan_thread,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            height=40,
            corner_radius=8,
            state="disabled"  # Inicia deshabilitado hasta tener ruta válida
        )
        self.scan_btn.pack(side="left", padx=(0, 10))

        # Botón Cuarentena: Estilo secundario delineado (outline) hasta que esté activo
        self.quarantine_btn = ctk.CTkButton(
            action_bar,
            text="📦 Enviar a Cuarentena",
            command=self._execute_quarantine,
            fg_color="transparent",
            border_width=2,
            border_color=("#EF4444", "#DC2626"),
            text_color=("#DC2626", "#F87171"),
            hover_color=("#FEE2E2", "#450A0A"),
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            height=40,
            corner_radius=8,
            state="disabled"
        )
        self.quarantine_btn.pack(side="left", padx=(0, 10))

        # Botón Restaurar: Delineado secundario
        self.restore_btn = ctk.CTkButton(
            action_bar,
            text="🔄 Restaurar desde Cuarentena",
            command=self._restore_from_manifest,
            fg_color="transparent",
            border_width=1,
            border_color=("gray75", "gray40"),
            text_color=("gray20", "gray85"),
            hover_color=("gray90", "gray25"),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            height=40,
            corner_radius=8
        )
        self.restore_btn.pack(side="left", padx=(0, 10))

        # Botón Exportar JSON
        self.export_btn = ctk.CTkButton(
            action_bar,
            text="💾 Exportar JSON",
            command=self._export_json_report,
            fg_color="transparent",
            border_width=1,
            border_color=("gray75", "gray40"),
            text_color=("gray20", "gray85"),
            hover_color=("gray90", "gray25"),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            height=40,
            corner_radius=8,
            state="disabled"
        )
        self.export_btn.pack(side="right")

    def _build_metrics_cards(self):
        metrics_container = ctk.CTkFrame(self.main_container, fg_color="transparent")
        metrics_container.pack(fill="x", pady=(0, 12))

        # Tarjetas con estilo accesible y tipografía bold de alto contraste
        self.card_files = self._create_metric_card(metrics_container, "Archivos Analizados", "0 (0 B)")
        self.card_groups = self._create_metric_card(metrics_container, "Grupos Duplicados", "0")
        self.card_redundant = self._create_metric_card(metrics_container, "Copias Redundantes", "0")
        self.card_recoverable = self._create_metric_card(
            metrics_container,
            "Espacio Recuperable",
            "0 B",
            accent_color=("#059669", "#10B981")
        )

    def _create_metric_card(
        self,
        parent: ctk.CTkFrame,
        title: str,
        initial_val: str,
        accent_color: tuple[str, str] | None = None
    ) -> ctk.CTkLabel:
        card = ctk.CTkFrame(
            parent,
            corner_radius=10,
            fg_color=("white", "#23272d"),
            border_width=1,
            border_color=("gray85", "#30363d")
        )
        card.pack(side="left", fill="both", expand=True, padx=4)

        title_lbl = ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("gray45", "gray65")
        )
        title_lbl.pack(anchor="center", pady=(10, 2))

        val_color = accent_color or ("#1D4ED8", "#60A5FA")
        val_lbl = ctk.CTkLabel(
            card,
            text=initial_val,
            font=ctk.CTkFont(family="Segoe UI", size=19, weight="bold"),
            text_color=val_color
        )
        val_lbl.pack(anchor="center", pady=(0, 12))

        return val_lbl

    def _build_progress_bar(self):
        prog_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        prog_frame.pack(fill="x", pady=(0, 10))

        self.progress_bar = ctk.CTkProgressBar(
            prog_frame,
            height=8,
            corner_radius=4,
            progress_color="#2563EB"
        )
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", pady=(0, 4))

        self.status_label = ctk.CTkLabel(
            prog_frame,
            text="Listo para auditar.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=("gray40", "gray70"),
            anchor="w"
        )
        self.status_label.pack(anchor="w")

    def _build_tabs_view(self):
        self.tabview = ctk.CTkTabview(
            self.main_container,
            corner_radius=10,
            fg_color=("white", "#23272d"),
            border_width=1,
            border_color=("gray85", "#30363d")
        )
        self.tabview.pack(fill="both", expand=True)

        tab_dups = self.tabview.add("Duplicados Encontrados")
        tab_log = self.tabview.add("Bitácora de Registro")

        # Pestaña 1: Tabla simplificada de duplicados (ocultando el hash completo de 64 caracteres)
        table_container = ctk.CTkFrame(tab_dups, fg_color="transparent")
        table_container.pack(fill="both", expand=True, padx=4, pady=4)

        # Dimensiones priorizadas: Grupo, Estado, Tamaño, Hash (8 chars), Ruta
        columns = ("group", "action", "size", "hash_short", "path")
        self.tree = ttk.Treeview(
            table_container,
            columns=columns,
            show="headings",
            selectmode="browse",
            style="Modern.Treeview"
        )

        self.tree.heading("group", text="Grupo")
        self.tree.heading("action", text="Acción")
        self.tree.heading("size", text="Tamaño")
        self.tree.heading("hash_short", text="Hash (8 car.)")
        self.tree.heading("path", text="Ruta del Archivo")

        self.tree.column("group", width=70, anchor="center")
        self.tree.column("action", width=140, anchor="center")
        self.tree.column("size", width=100, anchor="e")
        self.tree.column("hash_short", width=110, anchor="center")
        self.tree.column("path", width=580, anchor="w")

        tree_scroll_y = ttk.Scrollbar(table_container, orient="vertical", command=self.tree.yview)
        tree_scroll_x = ttk.Scrollbar(table_container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        tree_scroll_y.pack(side="right", fill="y")
        tree_scroll_x.pack(side="bottom", fill="x")
        self.tree.pack(side="left", fill="both", expand=True)

        # Pestaña 2: Bitácora de Registro
        self.log_textbox = ctk.CTkTextbox(
            tab_log,
            font=ctk.CTkFont(family="Consolas", size=12),
            corner_radius=8,
            wrap="word"
        )
        self.log_textbox.pack(fill="both", expand=True, padx=4, pady=4)

    def _setup_treeview_styles(self):
        """Aplica estilos visuales modernos a la tabla ttk acordes con el tema actual."""
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        is_dark = ctk.get_appearance_mode().lower() == "dark"

        bg_color = "#1c2128" if is_dark else "#ffffff"
        fg_color = "#f0f6fc" if is_dark else "#1f2937"
        heading_bg = "#2d333b" if is_dark else "#f3f4f6"
        heading_fg = "#c9d1d9" if is_dark else "#111827"
        selected_bg = "#1f6aa5" if is_dark else "#bfdbfe"
        selected_fg = "#ffffff" if is_dark else "#1e3a8a"

        style.configure(
            "Modern.Treeview",
            background=bg_color,
            fieldbackground=bg_color,
            foreground=fg_color,
            rowheight=30,
            font=("Segoe UI", 10),
            borderwidth=0
        )
        style.configure(
            "Modern.Treeview.Heading",
            background=heading_bg,
            foreground=heading_fg,
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padding=(6, 6)
        )
        style.map(
            "Modern.Treeview",
            background=[("selected", selected_bg)],
            foreground=[("selected", selected_fg)]
        )

        # Etiquetas de estado para filas
        keep_bg = "#064e3b" if is_dark else "#d1fae5"
        keep_fg = "#a7f3d0" if is_dark else "#065f46"
        quar_bg = "#78350f" if is_dark else "#fef3c7"
        quar_fg = "#fde68a" if is_dark else "#92400e"

        self.tree.tag_configure("keep", background=keep_bg, foreground=keep_fg)
        self.tree.tag_configure("quarantine", background=quar_bg, foreground=quar_fg)

    def _change_theme(self, mode: str):
        if mode == "Sistema":
            ctk.set_appearance_mode("System")
        elif mode == "Oscuro":
            ctk.set_appearance_mode("Dark")
        elif mode == "Claro":
            ctk.set_appearance_mode("Light")

        self.root.after(100, self._setup_treeview_styles)

    def _toggle_advanced_options(self):
        if self.is_advanced_open:
            self.advanced_frame.pack_forget()
            self.adv_btn.configure(text="⚙ Opciones avanzadas ▼")
            self.is_advanced_open = False
        else:
            self.advanced_frame.pack(fill="x", pady=(8, 0))
            self.adv_btn.configure(text="⚙ Opciones avanzadas ▲")
            self.is_advanced_open = True

    def _on_entry_key(self, event):
        path_str = self.path_entry.get().strip()
        self._validate_path_input(path_str)

    def _browse_directory(self):
        chosen = filedialog.askdirectory(title="Seleccionar carpeta a auditar")
        if chosen:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, chosen)
            self._validate_path_input(chosen)

    def _validate_path_input(self, path_str: str) -> bool:
        """
        Validación de entrada en línea (Inline Validation):
        Actualiza el mensaje en tiempo real sin popups bloqueantes.
        """
        if not path_str:
            self.validation_label.configure(
                text="Por favor seleccione una carpeta para comenzar.",
                text_color=("gray50", "gray65")
            )
            self.scan_btn.configure(state="disabled")
            self.current_base_dir = None
            return False

        try:
            validated = validate_target_path(path_str)
            self.validation_label.configure(
                text=f"✔ Carpeta válida y segura para auditar: {validated}",
                text_color=("#059669", "#10B981")
            )
            self.scan_btn.configure(state="normal")
            self.current_base_dir = validated
            return True
        except PermissionError as pe:
            self.validation_label.configure(
                text=f"⛔ Protegido por el sistema: {pe}",
                text_color=("#DC2626", "#EF4444")
            )
            self.scan_btn.configure(state="disabled")
            self.current_base_dir = None
            return False
        except FileNotFoundError:
            self.validation_label.configure(
                text="⚠ La carpeta especificada no existe en el almacenamiento.",
                text_color=("#D97706", "#F59E0B")
            )
            self.scan_btn.configure(state="disabled")
            self.current_base_dir = None
            return False
        except Exception as e:
            self.validation_label.configure(
                text=f"⚠ Ruta no válida: {e}",
                text_color=("#DC2626", "#EF4444")
            )
            self.scan_btn.configure(state="disabled")
            self.current_base_dir = None
            return False

    def _log(self, text: str):
        self.log_textbox.insert(tk.END, f"{text}\n")
        self.log_textbox.see(tk.END)

    def _start_scan_thread(self):
        if self.is_processing or not self.current_base_dir:
            return

        target_dir = self.current_base_dir
        rule_key = self.rule_combobox.get()
        keep_rule = RULE_LABELS.get(rule_key, KeepRule.DEEPEST_THEN_NEWEST.value)
        workers = get_safe_worker_count()

        self.is_processing = True
        self.scan_btn.configure(state="disabled")
        self.quarantine_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.progress_bar.set(0)
        self.status_label.configure(text="Iniciando escaneo y análisis por tamaño...")

        # Limpiar tabla
        for item in self.tree.get_children():
            self.tree.delete(item)

        self._log(f"\n--- Iniciando Auditoría Dry-Run en: {target_dir} ---")
        self._log(f"Criterio: {keep_rule} | Hilos de trabajo: {workers}")

        def worker():
            def progress_cb(done, total, fname):
                pct = (done / total) if total > 0 else 0
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

    def _update_progress(self, ratio: float, status_text: str):
        self.progress_bar.set(ratio)
        self.status_label.configure(text=status_text)

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

        # Poblar tabla simplificada (sin ruido del hash de 64 chars)
        for idx, g in enumerate(report["groups"], start=1):
            short_hash = g["hash_sha256"][:8] + "…"
            f_size = g["file_size_formatted"]

            # Fila conservada
            self.tree.insert(
                "",
                tk.END,
                values=(f"#{idx}", "KEEP (Conservar)", f_size, short_hash, g["kept_file"]),
                tags=("keep",)
            )

            # Filas redundantes
            for q_file in g["quarantine_files"]:
                self.tree.insert(
                    "",
                    tk.END,
                    values=("", "QUARANTINE", "", "", q_file),
                    tags=("quarantine",)
                )

        if meta["total_redundant_files"] > 0:
            # Activar botón de cuarentena con realce visual
            self.quarantine_btn.configure(
                state="normal",
                fg_color="#DC2626",
                text_color="#FFFFFF",
                hover_color="#B91C1C"
            )
            self.status_label.configure(
                text=f"Simulación completa: {meta['total_redundant_files']} archivos redundantes detectados. "
                     f"Espacio recuperable: {meta['recoverable_formatted']}."
            )
        else:
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

        # Confirmación amigable para el usuario
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
        keep_rule = RULE_LABELS.get(rule_key, KeepRule.DEEPEST_THEN_NEWEST.value)
        plan = build_audit_plan(self.last_duplicates, keep_rule=keep_rule)

        try:
            res: QuarantineResult = quarantine_redundant_files(self.current_base_dir, plan)
            self._log(f"\n✔ Cuarentena completada: {res.total_moved} archivos trasladados a {res.quarantine_dir}")
            self._log(f"  Manifiesto generado: {res.manifest_path}")

            messagebox.showinfo(
                "Cuarentena Exitosa",
                f"Se trasladaron {res.total_moved} archivos ({format_bytes(res.total_bytes_moved)}) a la carpeta de cuarentena.\n\n"
                f"Ubicación:\n{res.quarantine_dir}\n\n"
                f"Puede restaurarlos en cualquier momento utilizando el botón 'Restaurar desde Cuarentena'."
            )
            # Re-escanear para actualizar vista
            self._start_scan_thread()
        except Exception as e:
            messagebox.showerror("Error en Cuarentena", f"Ocurrió un error al mover los archivos: {e}")

    def _restore_from_manifest(self):
        manifest_file = filedialog.askopenfilename(
            title="Seleccionar archivo manifest.json de Cuarentena",
            filetypes=[("Archivo Manifiesto JSON", "manifest*.json"), ("Todos los archivos", "*.*")]
        )
        if not manifest_file:
            return

        try:
            res: RestoreResult = restore_from_quarantine(manifest_file)
            self._log(f"\n✔ Restauración completada: {res.total_restored} archivos devueltos a sus rutas originales.")
            if res.errors:
                for err in res.errors:
                    self._log(f"  [ADVERTENCIA] {err}")

            messagebox.showinfo(
                "Restauración Completada",
                f"Se restauraron {res.total_restored} archivos ({format_bytes(res.total_bytes_restored)}).\n"
                f"Archivos previamente restaurados: {res.skipped_count}\n"
                f"Conflictos o errores: {len(res.errors)}"
            )

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
            messagebox.showinfo("Exportación Exitosa", f"El reporte fue guardado correctamente en:\n{save_path}")

def launch_gui(initial_dir: str | None = None):
    root = ctk.CTk()
    app = DataCleanerGUI(root, initial_dir=initial_dir)
    root.mainloop()

if __name__ == "__main__":
    launch_gui()
