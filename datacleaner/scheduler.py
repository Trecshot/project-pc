"""
Subsistema de Tareas Programadas en Segundo Plano (Windows Task Scheduler API / Cron)
DataCleaner CLI/GUI

Permite registrar, consultar y eliminar tareas automatizadas en el Programador de Tareas
de Windows (`schtasks.exe`) para ejecutar auditorías y aislamientos en cuarentena
periódicos (DIARIO, SEMANAL, MENSUAL) sin necesidad de abrir la interfaz gráfica.
"""

from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys

from datacleaner.security import validate_target_path
from datacleaner.rules import KeepRule


DEFAULT_TASK_NAME = "DataCleaner_Automated_Audit"


@dataclass
class ScheduledTaskResult:
    success: bool
    task_name: str
    schedule_type: str
    start_time: str
    target_dir: str
    command_line: str
    message: str


def _resolve_background_python() -> str:
    """Prefiere pythonw.exe en Windows para ejecución silenciosa sin ventana de consola."""
    exe = Path(sys.executable)
    if sys.platform == "win32":
        pythonw = exe.with_name("pythonw.exe")
        if pythonw.exists():
            return str(pythonw)
    return str(exe)


def build_schtasks_create_command(
    target_dir: Path | str,
    schedule_type: str = "WEEKLY",
    start_time: str = "09:00",
    keep_rule: str = "deepest_then_newest",
    task_name: str = DEFAULT_TASK_NAME,
) -> list[str]:
    """
    Construye el vector de argumentos seguros para `schtasks /Create` en Windows.
    Valida previamente la ruta contra `validate_target_path` (Blacklist) y
    valida estrictamente la regla contra KeepRule para evitar inyecciones de comandos.
    """
    validated_dir = validate_target_path(target_dir)
    freq = schedule_type.upper().strip()
    if freq not in ("DAILY", "WEEKLY", "MONTHLY"):
        raise ValueError(f"Frecuencia no soportada: {schedule_type}. Use DAILY, WEEKLY o MONTHLY.")

    if isinstance(keep_rule, KeepRule):
        rule_val = keep_rule.value
    elif isinstance(keep_rule, str):
        try:
            rule_val = KeepRule(keep_rule).value
        except ValueError:
            valid_rules = ", ".join([r.value for r in KeepRule])
            raise ValueError(f"Regla de conservación inválida: '{keep_rule}'. Opciones válidas: {valid_rules}")
    else:
        raise ValueError(f"Tipo inválido para keep_rule: {type(keep_rule)}")

    if "__compiled__" in globals() or getattr(sys, "frozen", False):
        task_action = f'"{sys.executable}" quarantine "{validated_dir}" --keep-rule {rule_val} --yes'
    else:
        main_script = (Path(__file__).resolve().parent.parent / "main.py").resolve()
        py_bin = _resolve_background_python()
        task_action = f'"{py_bin}" "{main_script}" quarantine "{validated_dir}" --keep-rule {rule_val} --yes'

    return [
        "schtasks",
        "/Create",
        "/TN",
        task_name,
        "/TR",
        task_action,
        "/SC",
        freq,
        "/ST",
        start_time,
        "/F",
    ]


def register_scheduled_scan(
    target_dir: Path | str,
    schedule_type: str = "WEEKLY",
    start_time: str = "09:00",
    keep_rule: str = "deepest_then_newest",
    task_name: str = DEFAULT_TASK_NAME,
) -> ScheduledTaskResult:
    """Registra o actualiza la tarea programada en Windows Task Scheduler."""
    cmd = build_schtasks_create_command(
        target_dir=target_dir,
        schedule_type=schedule_type,
        start_time=start_time,
        keep_rule=keep_rule,
        task_name=task_name,
    )
    validated_str = str(validate_target_path(target_dir))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        ok = proc.returncode == 0
        output = (proc.stdout or proc.stderr or "").strip()
        return ScheduledTaskResult(
            success=ok,
            task_name=task_name,
            schedule_type=schedule_type.upper(),
            start_time=start_time,
            target_dir=validated_str,
            command_line=" ".join(cmd),
            message=output if output else ("Tarea programada registrada exitosamente." if ok else "Error al registrar tarea."),
        )
    except Exception as exc:
        return ScheduledTaskResult(
            success=False,
            task_name=task_name,
            schedule_type=schedule_type.upper(),
            start_time=start_time,
            target_dir=validated_str,
            command_line=" ".join(cmd),
            message=f"No se pudo invocar schtasks: {exc}",
        )


def query_scheduled_scan(task_name: str = DEFAULT_TASK_NAME) -> tuple[bool, str]:
    """Consulta si la tarea programada se encuentra activa en Windows Task Scheduler."""
    try:
        proc = subprocess.run(
            ["schtasks", "/Query", "/TN", task_name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0:
            return True, (proc.stdout or "Tarea activa.").strip()
        return False, "No hay ninguna tarea programada activa."
    except Exception as exc:
        return False, f"No se pudo consultar el Programador de Tareas: {exc}"


def remove_scheduled_scan(task_name: str = DEFAULT_TASK_NAME) -> tuple[bool, str]:
    """Elimina la tarea programada del Programador de Tareas de Windows."""
    try:
        proc = subprocess.run(
            ["schtasks", "/Delete", "/TN", task_name, "/F"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0:
            return True, (proc.stdout or "Tarea programada eliminada correctamente.").strip()
        return False, (proc.stderr or proc.stdout or "La tarea no existía o no pudo eliminarse.").strip()
    except Exception as exc:
        return False, f"Error al eliminar tarea programada: {exc}"
