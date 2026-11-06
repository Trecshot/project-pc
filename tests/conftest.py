"""
Configuración global de fixtures para pytest
DataCleaner Test Suite
"""

import pytest


@pytest.fixture(autouse=True)
def isolate_sqlite_db(tmp_path, monkeypatch):
    """
    Fuerza que pytest use siempre una base de datos SQLite temporal aislada
    para prevenir fugas forenses de datos o contaminación en .datacleaner.sqlite (Falla 4).
    """
    test_db = tmp_path / "test_datacleaner.sqlite"
    monkeypatch.setenv("DATACLEANER_DB_PATH", str(test_db))
