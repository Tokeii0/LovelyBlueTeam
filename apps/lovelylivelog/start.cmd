@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
  py -3 server.py
) else (
  where python >nul 2>nul
  if errorlevel 1 (
    echo 请先安装 Python 3.10 或更高版本，再重新打开本程序。
    pause
    exit /b 1
  )
  python server.py
)
if errorlevel 1 pause
