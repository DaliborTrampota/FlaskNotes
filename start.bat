@echo off
cd %~dp0
venv\scripts\activate.bat & python app.py
pause
