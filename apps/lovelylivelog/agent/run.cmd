@echo off
cd /d "%~dp0"
LogAgent.exe --config "%~dp0config.json"
pause
