@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if not errorlevel 1 (
  py -3 server.py --stop
) else (
  where python >nul 2>nul
  if errorlevel 1 (
    echo 未找到 Python，请在程序启动窗口按 Ctrl+C 停止。
    pause
    exit /b 1
  )
  python server.py --stop
)
if errorlevel 1 (
  pause
  exit /b 1
)
endlocal
