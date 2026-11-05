"""
Script de Compilación AOT (Ahead-of-Time) para DataCleaner Desktop (.exe)
Traduce el código Python a C y genera un ejecutable nativo independiente mediante Nuitka.

Uso:
    python build_executable.py
"""

import subprocess
import sys
from pathlib import Path


def get_nuitka_command(python_exe: str = sys.executable) -> list[str]:
    """Devuelve el comando oficial de compilación AOT con Nuitka sin consola en segundo plano."""
    return [
        python_exe,
        "-m",
        "nuitka",
        "--standalone",
        "--onefile",
        "--windows-console-mode=disable",
        "--enable-plugin=tk-inter",
        "--include-data-dir=datacleaner/assets=assets",
        "main.py",
    ]


def build() -> int:
    root_dir = Path(__file__).resolve().parent
    assets_dir = root_dir / "datacleaner" / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)

    cmd = get_nuitka_command()
    print("=" * 72)
    print("Compilando DataCleaner con Nuitka (AOT C Compiler)...")
    print("Comando:", " ".join(cmd))
    print("=" * 72)

    try:
        res = subprocess.run(cmd, cwd=str(root_dir), check=False)
        return res.returncode
    except FileNotFoundError as exc:
        print(f"Error al invocar Nuitka: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(build())
