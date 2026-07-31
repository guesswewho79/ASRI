$ErrorActionPreference = "Stop"
$env:ELECTRON_MIRROR = "https://npmmirror.com/mirrors/electron/"
$env:ELECTRON_BUILDER_BINARIES_MIRROR = "https://npmmirror.com/mirrors/electron-builder-binaries/"
npm install --registry=https://registry.npmmirror.com --no-audit --no-fund
npm run build:win
Write-Host "构建完成后，请查看 dist 目录。"
