const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Lista para guardar los nombres en la página web de logs
const executionLogs = [];

app.use(express.json());

// Página para ver los logs visualmente en: https://hubsilent-v2.onrender.com/logs
app.get('/logs', (req, res) => {
    let html = '<h1>Historial de Ejecuciones de mi Script</h1><ul>';
    if (executionLogs.length === 0) {
        html += '<li>Nadie ha ejecutado el script todavía.</li>';
    } else {
        executionLogs.forEach(log => {
            html += `<li><b>Usuario de Roblox:</b> ${log.player} — <b>Hora:</b> ${log.time}</li>`;
        });
    }
    html += '</ul>';
    res.send(html);
});

// Tu ruta exacta del script que registra al usuario
app.get('/api/script/98dc15a0a85ee7e6f51481a6e51b1527', (req, res) => {
    const playerName = req.query.player || "Anónimo";
    const timestamp = new Date().toLocaleString();
    
    // Guarda el registro para que aparezca en /logs y en la consola de Render
    executionLogs.unshift({ player: playerName, time: timestamp });
    console.log(`[EJECUCIÓN EXITOSA] Usuario: ${playerName} | Hora: ${timestamp}`);
    
    // AQUÍ VA EL CÓDIGO REAL DE TU SCRIPT DE ROBLOX (UI, AIMS, ETC.)
    const robloxScript = `
        print("¡Script cargado con éxito para ${playerName}!");
        -- PEGA AQUÍ TODO EL RESTO DE TU CÓDIGO DE LUAU
    `;
    
    res.setHeader('Content-Type', 'text/plain');
    res.send(robloxScript);
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
