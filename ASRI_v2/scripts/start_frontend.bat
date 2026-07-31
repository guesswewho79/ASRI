@echo off
setlocal EnableExtensions

cd /d "%~dp0\..\frontend"

where npm >nul 2>nul
if errorlevel 1 (
  echo [错误] 未找到Node.js/npm，请先安装Node.js 20.x LTS。
  pause
  exit /b 1
)

if not exist "node_modules" (
  echo [1/2] 正在安装Electron依赖...
  set "ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/"
  call npm install --registry=https://registry.npmmirror.com --no-audit --no-fund
  if errorlevel 1 goto failed
)

echo [2/2] 正在启动ASRI前端...
call npm start

goto end

:failed
echo [错误] 前端启动失败，请检查Node.js环境和网络连接。
pause
exit /b 1

:end
endlocal
