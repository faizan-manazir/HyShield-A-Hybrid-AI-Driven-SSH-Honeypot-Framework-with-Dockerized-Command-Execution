require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const { WebSocketServer } = require('ws');
const apiRoutes = require('./routes/api');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const allowedOrigins = new Set(
    (process.env.CORS_ORIGINS || 'http://localhost:3000')
      .split(',')
      .map((origin) => origin.trim())
      .filter(Boolean)
);

app.use(cors({
    origin(origin, callback) {
        // Non-browser clients may omit Origin; browser origins must be allow-listed.
        if (!origin || allowedOrigins.has(origin)) {
            return callback(null, true);
        }
        return callback(new Error('Origin not allowed by CORS'));
    }
}));
app.use(express.json());

// Routes
app.use('/api', apiRoutes);

// WebSocket for live updates
wss.on('connection', (ws) => {
    console.log('Client connected for live updates');
    ws.send(JSON.stringify({ type: 'connected', message: 'Connected to HyShield Live Stream' }));
    ws.on('close', () => console.log('Client disconnected'));
});

// Basic error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
});

const { migrate } = require('./db/migrate');
const IngestionService = require('./services/ingestion');
const path = require('path');

const PORT = process.env.PORT || 5000;
// Loopback is the safe default. Set HOST=0.0.0.0 only for an intentionally exposed/container deployment.
const HOST = process.env.HOST || '127.0.0.1';

async function startServer() {
    try {
        await migrate();
        
        const logPath = process.env.COWRIE_LOG_PATH || path.join(__dirname, 'cowrie.json');
        console.log(`[Config] Using Cowrie log path: ${logPath}`);
        
        const ingestor = new IngestionService(logPath);
        await ingestor.init();
        
        // Save globally if needed or just let it run
        global.ingestor = ingestor;
        
        server.listen(PORT, HOST, () => {
            console.log(`HyShield SIEM Backend running on ${HOST}:${PORT}`);
        });
    } catch (e) {
        console.error("Failed to start server:", e);
        process.exit(1);
    }
}

startServer();
