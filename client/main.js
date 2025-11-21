const { app, BrowserWindow, Menu } = require('electron');

function createWindow() {
    const win = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            nodeIntegration: true,
            devTools: !app.isPackaged // Disable DevTools in production
        }
    });

    // Remove default menu in production to prevent access to DevTools via menu
    if (app.isPackaged) {
        Menu.setApplicationMenu(null);
    }

    win.loadFile('renderer/index.html');
}

app.whenReady().then(createWindow);