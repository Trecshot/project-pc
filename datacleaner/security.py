"""
Módulo de Seguridad y Validación de Rutas (Blacklist Engine - Hardened)
DataCleaner CLI/GUI

Garantiza el aislamiento de rutas críticas del sistema operativo y particiones raíz.
Incluye normalización estricta de rutas relativas, resolución de enlaces simbólicos/uniones
y prevención de falsos negativos por diferencias de mayúsculas/minúsculas en Windows.
Cumple con RF-01, RF-02 y las directrices de hardening de seguridad.
"""

from pathlib import Path
import os
import platform
import tempfile
import sys


def _build_system_blacklist() -> list[Path]:
    """Construye dinámicamente la lista de rutas críticas del sistema operativo."""
    blacklist: list[Path] = []
    seen: set[str] = set()

    def add_path(p: Path | str | None):
        if not p:
            return
        try:
            path_obj = Path(p).resolve().absolute()
            p_str = str(path_obj).lower()
            if p_str not in seen:
                seen.add(p_str)
                blacklist.append(path_obj)
        except Exception:
            pass

    # Variables de entorno dinámicas en Windows
    win_env_vars = [
        "SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)",
        "ProgramW6432", "ProgramData", "APPDATA", "LOCALAPPDATA", "CommonProgramFiles"
    ]
    for env in win_env_vars:
        add_path(os.environ.get(env))

    # Rutas por defecto en la unidad del sistema de Windows
    sys_drive = os.environ.get("SystemDrive", "C:")
    for sub in [
        "Windows", "Program Files", "Program Files (x86)",
        "ProgramData", "Recovery", "System Volume Information", "$Recycle.Bin"
    ]:
        add_path(f"{sys_drive}/{sub}")

    # Unix / Linux / macOS
    unix_paths = [
        "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib",
        "/lib", "/lib64", "/boot", "/dev", "/proc", "/sys", "/root",
        "/System", "/Library"
    ]
    for u in unix_paths:
        add_path(u)

    return blacklist


def _build_system_root_blacklist() -> set[str]:
    """Rutas de nivel raíz del sistema operativo que no pueden ser abarcadas por un directorio padre."""
    roots: set[str] = set()
    sys_drive = os.environ.get("SystemDrive", "C:")
    for env in ["SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData"]:
        val = os.environ.get(env)
        if val:
            try:
                roots.add(str(Path(val).resolve().absolute()).lower())
            except Exception:
                pass
    for sub in ["Windows", "Program Files", "Program Files (x86)", "ProgramData", "Recovery", "System Volume Information", "$Recycle.Bin"]:
        try:
            roots.add(str(Path(f"{sys_drive}/{sub}").resolve().absolute()).lower())
        except Exception:
            pass
    for u in ["/etc", "/bin", "/sbin", "/usr", "/boot", "/dev", "/proc", "/sys", "/system", "/root"]:
        roots.add(u.lower())
    return roots


SYSTEM_ROOT_BLACKLIST = _build_system_root_blacklist()
SYSTEM_BLACKLIST = _build_system_blacklist()

def is_root_directory(target_path: Path) -> bool:
    """
    Determina si la ruta corresponde a una partición raíz o unidad completa de disco
    (por ejemplo 'C:\\', 'C:/' en Windows o '/' en sistemas Unix).
    """
    try:
        resolved = target_path.resolve().absolute()

        # En Windows, resolved.parent de 'C:\\' es 'C:\\'
        # En Unix, resolved.parent de '/' es '/'
        if resolved.parent == resolved:
            return True

        # Comprobación de ancla de unidad exacta
        clean_path = str(resolved).rstrip("\\/")
        clean_anchor = resolved.anchor.rstrip("\\/")
        if clean_path and clean_anchor and clean_path.lower() == clean_anchor.lower():
            return True

        return False
    except Exception:
        return True

def _is_subpath(child: Path, parent: Path) -> bool:
    """
    Comprueba de forma robusta y multiplataforma si 'child' es igual o está
    contenido dentro de 'parent'. Es insensible a mayúsculas/minúsculas en Windows.
    """
    try:
        child_res = child.resolve().absolute()
        parent_res = parent.resolve().absolute()

        is_windows = platform.system() == "Windows"

        if is_windows:
            child_parts = [p.lower() for p in child_res.parts]
            parent_parts = [p.lower() for p in parent_res.parts]
            if len(child_parts) >= len(parent_parts):
                if child_parts[:len(parent_parts)] == parent_parts:
                    return True
        else:
            try:
                child_res.relative_to(parent_res)
                return True
            except ValueError:
                pass

        return False
    except Exception:
        return False

def validate_target_path(target_path: str | Path, must_be_dir: bool = True) -> Path:
    """
    Valida y normaliza que la ruta objetivo sea segura para auditar.
    Lanza una excepción si la ruta está prohibida, es una unidad raíz,
    intenta escapar mediante rutas relativas hacia el sistema o no existe.

    Args:
        target_path: Ruta a validar en formato string o Path.
        must_be_dir: Si True, exige que sea un directorio existente.

    Returns:
        Path resuelta y normalizada estrictamente.

    Raises:
        ValueError: Si la ruta está vacía.
        FileNotFoundError: Si la ruta física no existe.
        NotADirectoryError: Si must_be_dir es True y la ruta es un archivo regular.
        PermissionError: Si la ruta es raíz de disco o viola la lista negra del sistema.
    """
    if not target_path or not str(target_path).strip():
        raise ValueError("La ruta del directorio objetivo no puede estar vacía.")

    # 1. Normalización previa de string para limpiar dobles barras y ./../
    norm_str = os.path.normpath(str(target_path).strip())

    # 2. Forzar resolución absoluta estricta
    resolved_target = Path(norm_str).expanduser().resolve().absolute()

    # 3. RF-01: Prohibir escaneo de discos completos o particiones raíz por defecto
    if is_root_directory(resolved_target):
        raise PermissionError(
            f"[SEGURIDAD CRÍTICA] Escaneo de disco completo o partición raíz bloqueado: '{resolved_target}'. "
            "El sistema requiere seleccionar un directorio específico para evitar bloqueos y riesgo de sistema."
        )

    # 4. RF-02: Validación contra Lista Negra de Seguridad (Blacklist)
    # CRIT-05 Hardening: No eximir %TEMP% globalmente en producción.
    # Permitir únicamente subdirectorios temporales con prefijo explícito de pruebas
    # (datacleaner_, dc_test_, pytest-) o cuando se ejecute con DATACLEANER_TEST_MODE=1.
    is_temp_child = False
    try:
        sys_temp = Path(tempfile.gettempdir()).resolve().absolute()
        if resolved_target != sys_temp and _is_subpath(resolved_target, sys_temp):
            is_test_env = (
                os.environ.get("DATACLEANER_TEST_MODE") == "1"
                or "pytest" in sys.modules
            )
            is_explicit_test_prefix = any(
                p.lower().startswith("datacleaner_")
                or p.lower().startswith("dc_test_")
                or p.lower().startswith("pytest-")
                for p in resolved_target.parts
            )
            if is_test_env or is_explicit_test_prefix:
                is_temp_child = True
    except Exception:
        pass

    for restricted in SYSTEM_BLACKLIST:
        restricted_resolved = restricted.resolve().absolute()

        # Omitir comprobaciones para subcarpetas de prueba temporales validadas
        if is_temp_child and _is_subpath(resolved_target, sys_temp):
            continue

        # 1. Bloquear siempre si intenta entrar DENTRO de cualquier ruta restringida (incluido AppData)
        if _is_subpath(resolved_target, restricted_resolved):
            raise PermissionError(
                f"[SEGURIDAD CRÍTICA] La ruta '{resolved_target}' está dentro de un directorio protegido "
                f"del sistema ('{restricted_resolved}') y no puede ser auditada ni modificada."
            )

        # 2. Bloquear si abarca un directorio crítico SOLO si es una raíz del sistema operativo
        # (permite escanear C:\Users\Usuario aunque contenga AppData, ya que scanner.py omite AppData)
        if str(restricted_resolved).lower() in SYSTEM_ROOT_BLACKLIST:
            if _is_subpath(restricted_resolved, resolved_target):
                raise PermissionError(
                    f"[SEGURIDAD CRÍTICA] La ruta '{resolved_target}' abarca un directorio crítico del sistema "
                    f"('{restricted_resolved}') y no puede ser auditada de manera recursiva."
                )

    # 5. Verificación de existencia física en almacenamiento
    if not resolved_target.exists():
        raise FileNotFoundError(f"La ruta especificada no existe: '{resolved_target}'")

    if must_be_dir and not resolved_target.is_dir():
        raise NotADirectoryError(f"La ruta especificada debe ser un directorio: '{resolved_target}'")

    return resolved_target
