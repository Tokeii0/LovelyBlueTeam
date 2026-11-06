@echo off
cd /d "%~dp0"
LogAgent.exe --install --config "%~dp0config.json"
pause
