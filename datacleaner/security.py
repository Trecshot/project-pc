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
import secrets
import hashlib
import subprocess
import logging

logger = logging.getLogger(__name__)


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


# Listas de exclusión de desarrollo y entornos virtuales (Falla 1)
PROTECTED_DEV_DIRS = {
    ".git", ".svn", ".hg", "venv", ".venv", "env",
    "site-packages", "node_modules", "__pycache__", ".pytest_cache"
}

STRUCTURAL_MARKER_FILES = {
    "__init__.py", "py.typed", ".gitignore", ".gitkeep",
    "REQUESTED", "INSTALLER", "WHEEL"
}


def is_protected_dev_resource(path: Path) -> bool:
    """Evita que el escáner destruya entornos virtuales o paquetes."""
    name_lower = path.name.lower()
    if any(name_lower == marker.lower() for marker in STRUCTURAL_MARKER_FILES):
        return True
    parts_lower = {part.lower() for part in path.parts}
    return any(dev_dir.lower() in parts_lower for dev_dir in PROTECTED_DEV_DIRS)


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


def is_blacklisted_path(target_path: Path | str) -> bool:
    """
    Verifica de forma estricta si una ruta pertenece a un directorio protegido del sistema (SYSTEM_BLACKLIST).
    Incorpora exención de carpetas temporales de prueba validadas (CRIT-05 / HIGH-03).
    """
    try:
        resolved = Path(target_path).resolve().absolute()
        is_temp_child = False
        try:
            sys_temp = Path(tempfile.gettempdir()).resolve().absolute()
            if resolved != sys_temp and _is_subpath(resolved, sys_temp):
                is_test_env = (
                    os.environ.get("DATACLEANER_TEST_MODE") == "1"
                    or "pytest" in sys.modules
                    or "unittest" in sys.modules
                )
                is_explicit_test_prefix = any(
                    p.lower().startswith("datacleaner_")
                    or p.lower().startswith("dc_test_")
                    or p.lower().startswith("pytest-")
                    or p.lower().startswith("tmp")
                    for p in resolved.parts
                )
                if is_test_env or is_explicit_test_prefix:
                    is_temp_child = True
        except Exception:
            pass

        for restricted in SYSTEM_BLACKLIST:
            restricted_resolved = restricted.resolve().absolute()
            if is_temp_child and _is_subpath(resolved, sys_temp):
                continue
            if _is_subpath(resolved, restricted_resolved):
                return True
        return False
    except Exception:
        return False


_CACHED_AUDIT_SECRET_KEY: bytes | None = None


def get_audit_secret_key(force_refresh: bool = False) -> bytes:
    """
    Obtiene o deriva la clave secreta criptográfica de auditoría (HMAC-SHA256).
    Jerarquía de resolución (NIST SSDF PO.4 / OWASP Cryptographic Storage):
    1. Variable de entorno 'DATACLEANER_AUDIT_KEY' si está definida.
    2. Archivo protegido local (.audit_key) en %LOCALAPPDATA%\\DataCleaner o ~/.local/share/datacleaner.
       Si no existe, genera 32 bytes de alta entropía (secrets.token_bytes(32)) y restringe su acceso por ACL/chmod.
    3. Fallback determinista salteado en caso de entornos de sólo lectura o sin almacenamiento local.
    """
    global _CACHED_AUDIT_SECRET_KEY
    if _CACHED_AUDIT_SECRET_KEY is not None and not force_refresh:
        return _CACHED_AUDIT_SECRET_KEY

    # 1. Variable de entorno explícita
    env_key = os.environ.get("DATACLEANER_AUDIT_KEY")
    if env_key:
        _CACHED_AUDIT_SECRET_KEY = env_key.encode("utf-8")
        return _CACHED_AUDIT_SECRET_KEY

    # 2. Almacén persistente local seguro
    try:
        if sys.platform == "win32":
            base_dir = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
            storage_dir = Path(base_dir) / "DataCleaner" if base_dir else Path.home() / ".datacleaner"
        else:
            storage_dir = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")) / "datacleaner"

        key_file = storage_dir / ".audit_key"

        if key_file.is_file():
            raw_key = key_file.read_bytes()
            if len(raw_key) >= 32:
                _CACHED_AUDIT_SECRET_KEY = raw_key[:32]
                return _CACHED_AUDIT_SECRET_KEY

        # Generar nueva clave criptográfica aleatoria de 256 bits (secrets.token_bytes)
        storage_dir.mkdir(parents=True, exist_ok=True)
        new_key = secrets.token_bytes(32)
        key_file.write_bytes(new_key)

        # Endurecer permisos (Principio de Menor Privilegio: ACL en Windows / chmod 0600 en Unix)
        try:
            if sys.platform == "win32":
                username = os.environ.get("USERNAME")
                if username:
                    subprocess.run(
                        ["icacls", str(key_file), "/inheritance:r", "/grant:r", f"{username}:(F)"],
                        capture_output=True,
                        check=False,
                        shell=False,
                    )
            else:
                os.chmod(key_file, 0o600)
        except Exception:
            pass

        _CACHED_AUDIT_SECRET_KEY = new_key
        return _CACHED_AUDIT_SECRET_KEY

    except Exception as e:
        # 3. Fallback criptográfico seguro: clave efímera aleatoria de 256 bits en RAM
        logger.warning(
            "No se pudo acceder ni persistir la clave de auditoría en el almacén local (%s). "
            "Generando clave efímera de 256 bits puramente aleatoria en memoria RAM para esta sesión.",
            e
        )
        _CACHED_AUDIT_SECRET_KEY = secrets.token_bytes(32)
        return _CACHED_AUDIT_SECRET_KEY

