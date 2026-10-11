require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const { WebSocketServer } = require('ws');
const apiRoutes = require('./routes/api');
const { createAuth } = require('./auth');

const auth = createAuth({
    username: process.env.SIEM_ADMIN_USERNAME,
    passwordHash: process.env.SIEM_ADMIN_PASSWORD_HASH,
    secret: process.env.SIEM_AUTH_SECRET
});

const app = express();
const server = http.createServer(app);

const allowedOrigins = new Set(
    (process.env.CORS_ORIGINS || 'http://localhost:3000')
      .split(',')
      .map((origin) => origin.trim())
      .filter(Boolean)
);

const isAllowedOrigin = (origin) => !origin || allowedOrigins.has(origin);
const wss = new WebSocketServer({
    server,
    verifyClient: (info, done) => {
        if (isAllowedOrigin(info.origin)) return done(true);
        return done(false, 403, 'Origin not allowed');
    }
});

// Reduce browser-side attack surface for API responses. These headers do not
// replace authentication or network-level access controls.
app.disable('x-powered-by');
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
});

app.use(cors({
    origin(origin, callback) {
        // Non-browser clients may omit Origin; browser origins must be allow-listed.
        if (isAllowedOrigin(origin)) {
            return callback(null, true);
        }
        return callback(new Error('Origin not allowed by CORS'));
    }
}));

// SIEM event payloads should be small; reject oversized JSON before route handling.
app.use(express.json({ limit: '1mb', strict: true }));

// Public health check and login; all other API routes require a valid short-lived bearer token.
app.post('/api/auth/login', auth.login);
app.use('/api', auth.requireAuth, apiRoutes);

// WebSocket clients must authenticate with a short-lived bearer token as their
// first message. Do not send live SIEM data or acknowledge the connection first.
const WS_AUTH_TIMEOUT_MS = 5000;
wss.on('connection', (ws) => {
    let authenticated = false;
    const authTimer = setTimeout(() => {
        if (!authenticated && ws.readyState === ws.OPEN) {
            ws.close(1008, 'Authentication required');
        }
    }, WS_AUTH_TIMEOUT_MS);

    ws.on('message', (raw) => {
        if (authenticated) return;
        let message;
        try {
            message = JSON.parse(raw.toString());
        } catch {
            ws.close(1008, 'Authentication required');
            return;
        }

        const token = message && message.type === 'auth' && typeof message.token === 'string'
            ? message.token
            : null;
        const principal = token ? auth.verifyBearerToken(token) : null;
        if (!principal) {
            clearTimeout(authTimer);
            ws.close(1008, 'Authentication required');
            return;
        }

        authenticated = true;
        clearTimeout(authTimer);
        ws.send(JSON.stringify({ type: 'connected', message: 'Connected to HyShield Live Stream' }));
        console.log('Authenticated client connected for live updates');
    });

    ws.on('close', () => {
        clearTimeout(authTimer);
        console.log('Client disconnected from live updates');
    });
});

// Return generic client errors; keep diagnostic details in server logs only.
app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);

    if (err && (err.type === 'entity.too.large' || err.status === 413)) {
        return res.status(413).json({ error: 'Request body too large' });
    }
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({ error: 'Invalid JSON body' });
    }
    if (err && err.message === 'Origin not allowed by CORS') {
        return res.status(403).json({ error: 'Origin not allowed' });
    }

    console.error('Unhandled API error:', err && err.stack ? err.stack : err);
    return res.status(500).json({ error: 'Internal Server Error' });
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

if (require.main === module) {
    startServer();
}

module.exports = { app, server, startServer, isAllowedOrigin, auth };
