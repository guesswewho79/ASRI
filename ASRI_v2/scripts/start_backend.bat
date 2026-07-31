@echo off
setlocal EnableExtensions

cd /d "%~dp0\.."

where python >nul 2>nul
if errorlevel 1 (
  echo [错误] 未找到Python，请先安装Python 3.10或更高版本，并勾选Add to PATH。
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo [1/3] 正在创建Python虚拟环境...
  python -m venv .venv
  if errorlevel 1 goto failed
)

echo [2/3] 正在安装或更新后端依赖...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip install -r backend\requirements.txt
if errorlevel 1 goto failed

echo [3/3] 正在启动ASRI真实算法后端...
echo 后端地址: http://127.0.0.1:8765
".venv\Scripts\python.exe" backend\main.py

goto end

:failed
echo [错误] 后端启动失败，请检查Python环境和网络连接。
pause
exit /b 1

:end
endlocal
