@echo off
chcp 65001 >nul
setlocal
title LovelyLivelog
cd /d "%~dp0"

echo ==========================================
echo   LovelyLivelog · 一键启动
echo ==========================================
echo.

rem ---- 1. 查找 Python 3.10+ ----
set "PY="
where py >nul 2>nul && py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul && set "PY=py -3"
if defined PY goto python_ok
where python >nul 2>nul && python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul && set "PY=python"
if defined PY goto python_ok
echo [错误] 未找到 Python 3.10 或更高版本。
echo        请从 https://www.python.org/downloads/ 安装，安装时勾选 "Add python.exe to PATH"。
goto fail

:python_ok
for /f "delims=" %%v in ('%PY% -c "import platform; print(platform.python_version())"') do echo [检查] Python %%v

rem ---- 2. 检查 .env 配置 ----
if exist ".env" goto env_exists
if not exist ".env.example" (
  echo [错误] 缺少 .env 和 .env.example，无法生成配置文件。
  goto fail
)
copy /y ".env.example" ".env" >nul
echo [配置] 已根据 .env.example 创建 .env。
goto need_key

:env_exists
findstr /r /c:"^PANEL_API_KEY=..*" ".env" >nul 2>nul && goto env_ok

:need_key
echo [配置] 请在打开的记事本中填写 PANEL_URL 和 PANEL_API_KEY，保存后关闭记事本。
start /wait notepad ".env"
findstr /r /c:"^PANEL_API_KEY=..*" ".env" >nul 2>nul && goto env_ok
echo [错误] .env 中的 PANEL_API_KEY 仍为空，请填写后重新运行本程序。
goto fail

:env_ok
echo [检查] 配置文件 .env 已就绪
if not exist "runtime" mkdir "runtime"

rem ---- 3. 启动（已在运行时 server.py 只会打开浏览器）----
echo.
echo [启动] 浏览器将自动打开；保留此窗口以持续收集和分析，按 Ctrl+C 停止。
echo.
%PY% server.py %*
if errorlevel 1 goto fail
goto end

:fail
echo.
echo 启动未完成，按任意键关闭窗口。
pause >nul
exit /b 1

:end
endlocal
