"""
Script de Compilación AOT (Ahead-of-Time) para DataCleaner Desktop (.exe)
Traduce el código Python a C y genera un ejecutable nativo independiente mediante Nuitka.

Uso:
    python build_executable.py
"""

import os
import subprocess
import sys
from pathlib import Path


def ensure_tcl_tk_bundle(root_dir: Path | None = None) -> tuple[Path | None, Path | None]:
    """
    Detecta las librerías físicas de Tcl/Tk.
    En Python 3.15 (o compilaciones con Tcl 9), las librerías están embebidas virtualmente
    en 'zipfs' (//zipfs:/lib/tcl/tcl_library), lo que impide que Nuitka las localice en disco.
    Esta función las extrae automáticamente a '.tcl_bundle/' garantizando compatibilidad total.
    """
    root = (root_dir or Path(__file__).resolve().parent).resolve()
    tcl_bundle = root / ".tcl_bundle"
    tcl_dir = tcl_bundle / "tcl"
    tk_dir = tcl_bundle / "tk"

    if (tcl_dir / "init.tcl").exists() and (tk_dir / "dialog.tcl").exists():
        return tcl_dir, tk_dir

    # Buscar en la instalación estándar de Python
    prefix = Path(sys.prefix)
    candidate_tcl = list(prefix.glob("tcl/tcl*"))
    candidate_tk = list(prefix.glob("tcl/tk*"))
    for ct in candidate_tcl:
        if (ct / "init.tcl").exists():
            for ck in candidate_tk:
                if (ck / "dialog.tcl").exists():
                    return ct, ck

    # Si no están físicamente en disco (caso zipfs en Python 3.15), extraer vía Tkinter
    try:
        import tkinter
        r = tkinter.Tk()
        r.withdraw()
        tcl_bundle.mkdir(parents=True, exist_ok=True)
        tcl_dir.mkdir(parents=True, exist_ok=True)
        tk_dir.mkdir(parents=True, exist_ok=True)
        # Extraer usando comandos nativos de Tcl sobre zipfs
        r.tk.call("file", "copy", "-force", "//zipfs:/lib/tcl/tcl_library", str(tcl_dir))
        r.tk.call("file", "copy", "-force", "//zipfs:/lib/tk/tk_library", str(tk_dir))
        r.destroy()

        # En caso de que se haya copiado la carpeta anidada
        if (tcl_dir / "tcl_library" / "init.tcl").exists():
            tcl_dir = tcl_dir / "tcl_library"
        if (tk_dir / "tk_library" / "dialog.tcl").exists():
            tk_dir = tk_dir / "tk_library"

        if (tcl_dir / "init.tcl").exists() and (tk_dir / "dialog.tcl").exists():
            return tcl_dir, tk_dir
    except Exception:
        pass

    return None, None


def get_nuitka_command(python_exe: str = sys.executable, root_dir: Path | None = None) -> list[str]:
    """Devuelve el comando oficial de compilación AOT con Nuitka sin consola en segundo plano."""
    root = (root_dir or Path(__file__).resolve().parent).resolve()
    cmd = [
        python_exe,
        "-m",
        "nuitka",
        "--standalone",
        "--onefile",
        "--windows-console-mode=disable",
        "--enable-plugin=tk-inter",
        "--include-data-dir=datacleaner/assets=assets",
        "--assume-yes-for-downloads",
    ]

    tcl_dir, tk_dir = ensure_tcl_tk_bundle(root)
    if tcl_dir and tk_dir:
        cmd.append(f"--tcl-library-dir={tcl_dir}")
        cmd.append(f"--tk-library-dir={tk_dir}")

    cmd.append("main.py")
    return cmd


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
