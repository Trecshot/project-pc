"""
Módulo de Seguridad y Validación de Rutas (Blacklist Engine)
DataCleaner CLI/GUI

Garantiza el aislamiento de rutas críticas del sistema operativo y particiones raíz.
Cumple con RF-01 y RF-02 de la especificación técnica.
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
    (por ejemplo 'C:\\' en Windows o '/' en sistemas Unix).
    """
    resolved = target_path.resolve()
    # En Windows, resolved.parent de 'C:\\' es 'C:\\'
    # En Unix, resolved.parent de '/' es '/'
    if resolved.parent == resolved:
        return True
    
    # Comprobación de ancla de unidad exacta
    if str(resolved).rstrip("\\/") == resolved.anchor.rstrip("\\/"):
        return True
        
    return False

def validate_target_path(target_path: str | Path, must_be_dir: bool = True) -> Path:
    """
    Valida que la ruta objetivo sea segura para auditar.
    Lanza una excepción si la ruta está prohibida, es una unidad raíz,
    intenta escapar hacia el sistema o no existe.

    Args:
        target_path: Ruta a validar en formato string o Path.
        must_be_dir: Si True, exige que sea un directorio existente.

    Returns:
        Path resuelta y validada.

    Raises:
        FileNotFoundError: Si la ruta no existe en el almacenamiento.
        NotADirectoryError: Si must_be_dir es True y la ruta es un archivo regular.
        PermissionError: Si la ruta es raíz de disco o está en la lista negra del sistema.
    """
    if not target_path:
        raise ValueError("La ruta del directorio objetivo no puede estar vacía.")

    resolved_target = Path(target_path).expanduser().resolve()

    # RF-01: Prohibir escaneo de discos completos o particiones raíz por defecto
    if is_root_directory(resolved_target):
        raise PermissionError(
            f"[SEGURIDAD CRÍTICA] Escaneo de disco completo o partición raíz bloqueado: '{resolved_target}'. "
            "El sistema requiere seleccionar un directorio específico para evitar bloqueos y riesgo de sistema."
        )

    # RF-02: Validación contra Lista Negra de Seguridad
    for restricted in SYSTEM_BLACKLIST:
        # Se normaliza la ruta restringida
        restricted_resolved = restricted.resolve()
        
        # 1. Comprueba si la ruta objetivo está contenida dentro de una ruta restringida
        try:
            resolved_target.relative_to(restricted_resolved)
            raise PermissionError(
                f"[SEGURIDAD CRÍTICA] La ruta '{resolved_target}' está dentro de un directorio protegido "
                f"del sistema ('{restricted_resolved}') y no puede ser auditada ni modificada."
            )
        except ValueError:
            pass

        # 2. Comprueba si la ruta objetivo contiene a una ruta restringida (por ejemplo un contenedor directo)
        try:
            restricted_resolved.relative_to(resolved_target)
            raise PermissionError(
                f"[SEGURIDAD CRÍTICA] La ruta '{resolved_target}' abarca un directorio crítico del sistema "
                f"('{restricted_resolved}') y no puede ser auditada de manera recursiva."
            )
        except ValueError:
            pass

    # Verificación de existencia física
    if not resolved_target.exists():
        raise FileNotFoundError(f"La ruta especificada no existe: '{resolved_target}'")

    if must_be_dir and not resolved_target.is_dir():
        raise NotADirectoryError(f"La ruta especificada debe ser un directorio: '{resolved_target}'")

    return resolved_target
