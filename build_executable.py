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


def generate_sbom(root_dir: Path) -> Path:
    """Genera un archivo SBOM normalizado CycloneDX JSON (NIST SSDF PS.3.2 / CNCF)."""
    dist_dir = root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    sbom_path = dist_dir / "datacleaner_sbom.json"

    print("[SBOM] Generando Software Bill of Materials (CycloneDX)...")
    try:
        subprocess.run(
            [
                sys.executable, "-m", "cyclonedx_py",
                "pip",
                "--output-file", str(sbom_path),
                "--output-format", "JSON"
            ],
            cwd=str(root_dir),
            check=True
        )
        print(f"[SBOM] Generado exitosamente en: {sbom_path}")
        return sbom_path
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[SBOM][ADVERTENCIA] No se pudo generar automáticamente el SBOM: {e}")
        return sbom_path


def sign_artifact(binary_path: Path) -> bool:
    """
    Aplica firma digital Authenticode (NIST SSDF PS.1.1 / CNCF Artifact Trust).
    Usa el certificado empresarial configurado en el entorno de compilación.
    """
    if sys.platform != "win32" or not binary_path.exists():
        return False

    cert_thumbprint = os.environ.get("CODESIGN_THUMBPRINT")
    timestamp_server = os.environ.get("CODESIGN_TS_URL", "http://timestamp.digicert.com")

    if not cert_thumbprint:
        print("[CODE-SIGN][AVISO] CODESIGN_THUMBPRINT no está configurado. El binario no fue firmado.")
        return False

    print(f"[CODE-SIGN] Firmando digitalmente {binary_path.name}...")
    cmd = [
        "signtool.exe", "sign",
        "/sha1", cert_thumbprint,
        "/tr", timestamp_server,
        "/td", "SHA256",
        "/fd", "SHA256",
        str(binary_path)
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print("[CODE-SIGN] Binario firmado satisfactoriamente.")
        return True
    else:
        print(f"[CODE-SIGN][ERROR] Error de firma: {res.stderr}")
        return False


def clean_workspace_artifacts(root_dir: Path | None = None) -> int:
    """
    Limpia artefactos binarios compilados y bases de datos locales del árbol de trabajo (Auditoría A).
    Elimina archivos *.pyc, carpetas __pycache__, .datacleaner.sqlite* y .pytest_cache
    para evitar fuga de rutas locales y sobrepeso en la distribución.
    """
    root = (root_dir or Path(__file__).resolve().parent).resolve()
    removed_count = 0
    import shutil

    # Eliminar carpetas de caché y artefactos temporales/ocultos (Auditoría A / LOW-02)
    dirs_to_clean = (
        list(root.rglob("__pycache__"))
        + list(root.glob(".pytest_cache"))
        + list(root.glob(".tcl_bundle"))
    )
    for cache_dir in dirs_to_clean:
        if cache_dir.exists():
            try:
                shutil.rmtree(cache_dir, ignore_errors=True)
                removed_count += 1
            except Exception:
                pass

    # Eliminar archivos .pyc sueltos y bases SQLite locales
    for f in list(root.rglob("*.pyc")) + list(root.rglob("*.pyo")):
        if f.is_file():
            try:
                f.unlink(missing_ok=True)
                removed_count += 1
            except Exception:
                pass

    for f in root.iterdir():
        if f.is_file() and f.name.startswith(".datacleaner.sqlite"):
            try:
                if sys.platform == "win32":
                    subprocess.run(["icacls", str(f), "/reset"], capture_output=True, check=False)
                f.unlink(missing_ok=True)
                removed_count += 1
            except Exception:
                pass

    return removed_count


def build() -> int:
    root_dir = Path(__file__).resolve().parent
    # Limpieza previa de artefactos binarios y cachés locales (Auditoría A)
    cleaned = clean_workspace_artifacts(root_dir)
    if cleaned > 0:
        print(f"[CLEANUP] Eliminados {cleaned} artefactos/directorios de caché residuales.")

    assets_dir = root_dir / "datacleaner" / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)

    # Generar SBOM previo al empaquetado final (NIST SSDF PS.3.2)
    generate_sbom(root_dir)

    cmd = get_nuitka_command()
    print("=" * 72)
    print("Compilando DataCleaner con Nuitka (AOT C Compiler)...")
    print("Comando:", " ".join(cmd))
    print("=" * 72)

    try:
        res = subprocess.run(cmd, cwd=str(root_dir), check=False)
        if res.returncode == 0:
            # Ubicar el binario compilado y aplicar firma Authenticode (NIST SSDF PS.1.1)
            binary_candidates = [
                root_dir / "main.exe",
                root_dir / "DataCleaner.exe",
                root_dir / "dist" / "main.exe",
            ]
            for candidate in binary_candidates:
                if candidate.exists():
                    sign_artifact(candidate)
                    break
        return res.returncode
    except FileNotFoundError as exc:
        print(f"Error al invocar Nuitka: {exc}")
        return 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--clean", "-c"):
        n = clean_workspace_artifacts()
        print(f"[CLEANUP] Árbol de trabajo limpio: {n} artefactos/cachés eliminados.")
        sys.exit(0)
    sys.exit(build())
