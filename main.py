#!/usr/bin/env python3
"""
DataCleaner: Gestor Local de Organización y Auditoría de Archivos por Hash (SHA-256)
Punto de Entrada Principal (CLI & GUI)
"""

import sys
from datacleaner.cli import main as cli_main

if __name__ == "__main__":
    # Si se invoca sin argumentos en un entorno interactivo de escritorio, se puede iniciar la GUI
    if len(sys.argv) == 1:
        # Si se ejecuta haciendo doble clic en Windows (sin argumentos de consola),
        # podemos lanzar la GUI directamente o mostrar el menú CLI
        try:
            from datacleaner.gui import launch_gui
            launch_gui()
        except Exception:
            cli_main()
    elif len(sys.argv) == 2 and sys.argv[1] in ("--gui", "-g"):
        from datacleaner.gui import launch_gui
        launch_gui()
    else:
        cli_main()
