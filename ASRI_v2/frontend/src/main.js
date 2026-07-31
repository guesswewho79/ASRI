const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs/promises');

let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1480,
    height: 920,
    minWidth: 1180,
    minHeight: 760,
    title: '政务外网攻击面智能预测与收敛系统',
    backgroundColor: '#0f172a',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  mainWindow.removeMenu();
  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });
}

app.whenReady().then(() => {
  app.setName('政务外网攻击面智能预测与收敛系统');
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

ipcMain.handle('app:get-info', () => ({
  name: '政务外网攻击面智能预测与收敛系统',
  version: app.getVersion(),
  platform: process.platform,
  arch: process.arch
}));

ipcMain.handle('file:open-json', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: '导入攻击图数据',
    filters: [
      { name: 'JSON数据', extensions: ['json'] },
      { name: '全部文件', extensions: ['*'] }
    ],
    properties: ['openFile']
  });

  if (result.canceled || !result.filePaths.length) return null;
  const filePath = result.filePaths[0];
  const content = await fs.readFile(filePath, 'utf8');
  return { filePath, content };
});

ipcMain.handle('file:save', async (_event, payload) => {
  const { defaultFileName, content, filters } = payload;
  const result = await dialog.showSaveDialog(mainWindow, {
    title: '导出文件',
    defaultPath: defaultFileName,
    filters: filters || [{ name: '全部文件', extensions: ['*'] }]
  });

  if (result.canceled || !result.filePath) return null;
  await fs.writeFile(result.filePath, content, 'utf8');
  return result.filePath;
});
