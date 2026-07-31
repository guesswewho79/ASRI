$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
$BackendScript = Join-Path $RootDir "scripts\start_backend.bat"
$FrontendScript = Join-Path $RootDir "scripts\start_frontend.bat"

Write-Host "正在启动ASRI v2.0真实算法后端..."
Start-Process -FilePath "cmd.exe" -ArgumentList "/k", "`"$BackendScript`"" -WorkingDirectory $RootDir

Write-Host "等待后端初始化..."
Start-Sleep -Seconds 8

Write-Host "正在启动ASRI v2.0前端..."
Start-Process -FilePath "cmd.exe" -ArgumentList "/k", "`"$FrontendScript`"" -WorkingDirectory $RootDir

Write-Host ""
Write-Host "启动命令已发出。"
Write-Host "后端地址: http://127.0.0.1:8765"
Write-Host "前端启动后，请进入左侧“真实算法”页面。"
