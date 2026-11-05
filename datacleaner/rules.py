"""
Criterios de Permanencia y Selección de Duplicados (Keep Rules)
DataCleaner CLI/GUI

Determina automáticamente cuál archivo del grupo de colisiones sobrevive (Keep)
y cuáles son candidatos a trasladarse a Cuarentena según profundidad, limpieza
de ruta y fecha de modificación. Cumple con la Sección 7 de la especificación técnica.
"""

from pathlib import Path
from enum import Enum
import os
import re

class KeepRule(str, Enum):
    DEEPEST_THEN_NEWEST = "deepest_then_newest"
    DEEPEST_THEN_OLDEST = "deepest_then_oldest"
    SHALLOWEST_THEN_NEWEST = "shallowest_then_newest"
    NEWEST_ONLY = "newest"
    OLDEST_ONLY = "oldest"

# Palabras clave en rutas que denotan ubicaciones provisionales o secundarias
SUSPICIOUS_PATH_KEYWORDS = {
    "temp", "tmp", "download", "downloads", "descargas",
    "cache", "copia", "copy", "bak", "backup", "descartes"
}

def calculate_path_cleanliness_score(path: Path, base_dir: Path | None = None) -> int:
    """
    Asigna un puntaje de idoneidad según la estructura de la ruta.
    Rutas estructuradas en carpetas de proyectos reciben mejor puntaje que
    rutas temporales o de descargas.
    Utiliza tokenización delimitada por espacios, guiones o puntos para evitar falsos
    positivos con palabras como 'Templates', 'Temporada_1', 'Copyright' o 'Microscopio'.
    """
    score = 0
    resolved_path = path.resolve()
    if base_dir:
        try:
            rel_path = resolved_path.relative_to(Path(base_dir).resolve())
            parts_to_evaluate = rel_path.parts
        except ValueError:
            parts_to_evaluate = resolved_path.parts
    else:
        parts_to_evaluate = resolved_path.parts

    # Penalizar si contiene componentes o tokens provisionales
    for part in parts_to_evaluate:
        tokens = set(re.split(r'[\s_\-\.]+', part.lower()))
        if any(keyword in tokens for keyword in SUSPICIOUS_PATH_KEYWORDS):
            score -= 100

    # Favorecer rutas con profundidad organizativa (más niveles de subdirectorios)
    score += len(parts_to_evaluate) * 10
    return score

def get_file_mtime(path: Path) -> float:
    """Obtiene la fecha de última modificación de un archivo de manera segura."""
    try:
        return path.stat().st_mtime
    except (OSError, PermissionError):
        return 0.0

def select_file_to_keep(
    paths: list[Path],
    rule: KeepRule | str = KeepRule.DEEPEST_THEN_NEWEST,
    base_dir: Path | None = None
) -> tuple[Path, list[Path]]:
    """
    Selecciona el archivo superviviente y los archivos a aislar en cuarentena
    según la regla especificada.

    Args:
        paths: Lista de rutas con contenido binario idéntico.
        rule: Regla de selección (KeepRule o string coincidente).
        base_dir: Directorio base opcional para calcular rutas relativas limpias.

    Returns:
        Tupla: (archivo_a_conservar, lista_archivos_a_cuarentena)
    """
    if not paths:
        raise ValueError("La lista de rutas no puede estar vacía.")
    if len(paths) == 1:
        return paths[0], []

    if isinstance(rule, str):
        try:
            rule = KeepRule(rule)
        except ValueError:
            rule = KeepRule.DEEPEST_THEN_NEWEST

    def sort_key(p: Path):
        mtime = get_file_mtime(p)
        clean_score = calculate_path_cleanliness_score(p, base_dir=base_dir)
        depth = len(p.parts)

        if rule == KeepRule.DEEPEST_THEN_NEWEST:
            # Mayor puntaje de limpieza primero, luego mayor mtime, luego orden alfabético
            return (clean_score, mtime, -len(str(p)), str(p))
        elif rule == KeepRule.DEEPEST_THEN_OLDEST:
            # Mayor puntaje de limpieza primero, luego menor mtime
            return (clean_score, -mtime, -len(str(p)), str(p))
        elif rule == KeepRule.SHALLOWEST_THEN_NEWEST:
            # Menor profundidad, mayor mtime
            return (-depth, mtime, str(p))
        elif rule == KeepRule.NEWEST_ONLY:
            return (mtime, clean_score, str(p))
        elif rule == KeepRule.OLDEST_ONLY:
            return (-mtime, clean_score, str(p))
        else:
            return (clean_score, mtime, str(p))

    # Ordenar y seleccionar el mejor elemento (máximo según sort_key)
    sorted_paths = sorted(paths, key=sort_key, reverse=True)
    kept_file = sorted_paths[0]
    quarantine_files = sorted_paths[1:]

    return kept_file, quarantine_files
