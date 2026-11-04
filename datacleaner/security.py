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

# Lista de directorios críticos del sistema protegidos por defecto
SYSTEM_BLACKLIST = [
    # Windows
    Path("C:/Windows"),
    Path("C:/Program Files"),
    Path("C:/Program Files (x86)"),
    Path("C:/ProgramData"),
    Path("C:/Recovery"),
    Path("C:/System Volume Information"),
    # Unix / Linux / macOS
    Path("/etc"),
    Path("/bin"),
    Path("/sbin"),
    Path("/usr/bin"),
    Path("/usr/sbin"),
    Path("/usr/lib"),
    Path("/lib"),
    Path("/lib64"),
    Path("/boot"),
    Path("/dev"),
    Path("/proc"),
    Path("/sys"),
    Path("/root"),
    Path("/System"),
    Path("/Library"),
]

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
    for restricted in SYSTEM_BLACKLIST:
        restricted_resolved = restricted.resolve().absolute()

        # Comprueba si la ruta objetivo está dentro de una ruta restringida
        if _is_subpath(resolved_target, restricted_resolved):
            raise PermissionError(
                f"[SEGURIDAD CRÍTICA] La ruta '{resolved_target}' está dentro de un directorio protegido "
                f"del sistema ('{restricted_resolved}') y no puede ser auditada ni modificada."
            )

        # Comprueba si la ruta objetivo abarca o es padre de una ruta restringida
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
