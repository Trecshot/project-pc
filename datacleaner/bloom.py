"""
Módulo de Filtro de Bloom Probabilístico de Alta Eficiencia (RAM O(1))
DataCleaner CLI/GUI

Implementa un Filtro de Bloom optimizado en memoria RAM mediante `bytearray`
y doble hashing (técnica Kirsch-Mitzenmacher), permitiendo descartar elementos únicos
con huella de memoria casi nula sin saturar la memoria RAM en auditorías masivas
de cientos de miles o millones de archivos.
"""

import math
import hashlib
from typing import Any


class BloomFilter:
    """
    Filtro de Bloom probabilístico en memoria.
    Garantía: Falsos positivos controlados (p), cero falsos negativos.
    Si el filtro indica que un elemento NO está presente, es 100% seguro que no existe.
    """

    def __init__(self, expected_elements: int = 1_000_000, false_positive_rate: float = 0.01):
        if expected_elements <= 0:
            expected_elements = 10_000
        if not (0.0 < false_positive_rate < 1.0):
            false_positive_rate = 0.01

        self.expected_elements = expected_elements
        self.false_positive_rate = false_positive_rate

        # Fórmula óptima de bits m = - (n * ln(p)) / (ln(2)^2)
        m = - (expected_elements * math.log(false_positive_rate)) / (math.log(2) ** 2)
        self.size_bits = max(64, int(math.ceil(m)))
        # Número óptimo de funciones hash k = (m / n) * ln(2)
        k = (self.size_bits / expected_elements) * math.log(2)
        self.hash_count = max(1, min(int(round(k)), 16))

        # Almacenamiento en bytearray compacto (1 byte = 8 bits)
        self.size_bytes = (self.size_bits + 7) // 8
        self.bit_array = bytearray(self.size_bytes)
        self._count = 0

    def _get_hashes(self, item: Any) -> list[int]:
        """Genera k índices de bits usando doble hashing (Kirsch-Mitzenmacher) de alta velocidad sin SHA-256."""
        if isinstance(item, int):
            val = item & 0xFFFFFFFFFFFFFFFF
            h1 = ((val ^ (val >> 30)) * 0xbf58476d1ce4e5b9) & 0xFFFFFFFFFFFFFFFF
            h1 = ((h1 ^ (h1 >> 27)) * 0x94d049bb133111eb) & 0xFFFFFFFFFFFFFFFF
            h1 ^= (h1 >> 31)
            h2 = ((val ^ 0x9e3779b97f4a7c15) * 0xbf58476d1ce4e5b9) & 0xFFFFFFFFFFFFFFFF
            h2 = ((h2 ^ (h2 >> 27)) * 0x94d049bb133111eb) & 0xFFFFFFFFFFFFFFFF
            h2 ^= (h2 >> 31)
            h2 = h2 or 1
        else:
            if isinstance(item, bytes):
                data = item
            elif isinstance(item, str):
                data = item.encode("utf-8")
            else:
                data = str(item).encode("utf-8")
            # FNV-1a 64-bit hash
            h1 = 0xcbf29ce484222325
            for b in data:
                h1 = ((h1 ^ b) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
            h2 = ((h1 * 0x9e3779b97f4a7c15) >> 16) & 0xFFFFFFFFFFFFFFFF
            h2 = h2 or 1

        indices = []
        for i in range(self.hash_count):
            combined = (h1 + i * h2) % self.size_bits
            indices.append(combined)
        return indices

    def add(self, item: Any) -> None:
        """Agrega un elemento al filtro de Bloom activando sus k bits correspondientes."""
        for bit_index in self._get_hashes(item):
            byte_idx = bit_index // 8
            bit_offset = bit_index % 8
            self.bit_array[byte_idx] |= (1 << bit_offset)
        self._count += 1

    def __contains__(self, item: Any) -> bool:
        """Verifica si un elemento podría estar presente (True) o definitivamente no está (False)."""
        for bit_index in self._get_hashes(item):
            byte_idx = bit_index // 8
            bit_offset = bit_index % 8
            if not (self.bit_array[byte_idx] & (1 << bit_offset)):
                return False
        return True

    @property
    def approximate_count(self) -> int:
        return self._count

    @property
    def memory_bytes(self) -> int:
        """Retorna el peso total exacto de la estructura en bytes de memoria RAM."""
        return self.size_bytes
