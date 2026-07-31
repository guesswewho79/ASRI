const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('desktopApi', {
  getAppInfo: () => ipcRenderer.invoke('app:get-info'),
  openJsonFile: () => ipcRenderer.invoke('file:open-json'),
  saveFile: (payload) => ipcRenderer.invoke('file:save', payload)
});
