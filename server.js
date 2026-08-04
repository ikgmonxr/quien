const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Lista en memoria para guardar los registros
const executionLogs = [];

app.use(express.json());

// Página principal
app.get('/', (req, res) => {
    res.send('¡Servidor de Roblox activo y funcionando correctamente!');
});

// NUEVA PÁGINA: Si entras a tuenlace.onrender.com/logs verás la lista en pantalla
app.get('/logs', (req, res) => {
    let html = '<h1>Historial de Ejecuciones de Roblox</h1><ul>';
    if (executionLogs.length === 0) {
        html += '<li>Aún nadie ha ejecutado el script.</li>';
    } else {
        executionLogs.forEach(log => {
            html += `<li><b>Usuario:</b> ${log.player} — <b>Hora:</b> ${log.time}</li>`;
        });
    }
    html += '</ul>';
    res.send(html);
});

// Endpoint que entrega el script y registra al jugador
app.get('/script', (req, res) => {
    const playerName = req.query.player || "Anónimo";
    const timestamp = new Date().toLocaleString();
    
    // Guarda el registro en la lista y en la consola de Render
    executionLogs.unshift({ player: playerName, time: timestamp }); // Añade el más reciente arriba
    console.log(`[EJECUCIÓN EXITOSA] Usuario: ${playerName} | Hora: ${timestamp}`);
    
    // AQUÍ COLOCAS EL CÓDIGO DE TU SCRIPT DE ROBLOX (LUAU)
    const robloxScript = `
        print("¡Script cargado con éxito para ${playerName}!");
        -- Pega aquí el resto de tu código o interfaz gráfica (UI)
    `;
    
    res.setHeader('Content-Type', 'text/plain');
    res.send(robloxScript);
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
