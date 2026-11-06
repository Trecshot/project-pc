@echo off
cd /d "%~dp0"
title Iniciar DataCleaner

REM Verificar si existe el entorno virtual local
if exist ".venv\Scripts\pythonw.exe" (
    start "" ".venv\Scripts\pythonw.exe" main.py
    exit /b 0
)

if exist ".venv\Scripts\python.exe" (
    start "" ".venv\Scripts\python.exe" main.py
    exit /b 0
)

REM En caso contrario, usar el Python del sistema
start "" pythonw main.py 2>nul || python main.py
