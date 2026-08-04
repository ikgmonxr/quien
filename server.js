const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Endpoint principal que recibe al usuario y entrega el script
app.get('/script', (req, res) => {
    const playerName = req.query.player || "Anónimo";
    const timestamp = new Date().toLocaleString();
    
    // Esto se imprimirá en los Logs de tu panel de Render en tiempo real
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
