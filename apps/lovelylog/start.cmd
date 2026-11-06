@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist config.local.json copy /y config.example.json config.local.json >nul
start "" http://127.0.0.1:8790
LovelyLog.exe -config config.local.json
pause
