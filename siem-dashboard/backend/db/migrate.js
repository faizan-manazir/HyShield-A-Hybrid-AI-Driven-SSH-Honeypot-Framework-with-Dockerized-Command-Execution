const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const path = require('path');
const fs = require('fs');

let sharedDb = null;

async function getDb() {
    if (sharedDb) return sharedDb;
    const dbPath = process.env.DB_PATH || path.join(__dirname, '..', 'hyshield.db');
    sharedDb = await open({
        filename: dbPath,
        driver: sqlite3.Database
    });
    return sharedDb;
}

async function migrate() {
    const db = await getDb();
    
    // Enable WAL mode for better concurrency
    await db.exec('PRAGMA journal_mode = WAL');

    // 1. Raw Events
    // Preserves the original event payload exactly as received.
    await db.exec(`
        CREATE TABLE IF NOT EXISTS raw_events (
            id TEXT PRIMARY KEY, /* e.g. a hash of the event or source-provided ID */
            session_id TEXT,
            timestamp DATETIME,
            eventid TEXT,
            payload JSON,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_raw_session ON raw_events(session_id);
    `);

    // 2. Normalized Sessions (Metadata & Status)
    await db.exec(`
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            src_ip TEXT,
            start_time DATETIME,
            end_time DATETIME,
            is_closed BOOLEAN DEFAULT 0,
            threat_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'LOW',
            summary JSON,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    // 3. Alerts
    await db.exec(`
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            session_id TEXT,
            severity TEXT,
            title TEXT,
            reason TEXT,
            mitre TEXT,
            status TEXT DEFAULT 'OPEN',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);
    `);

    // 4. Ingestion Checkpoints
    const tableInfo = await db.all("PRAGMA table_info(checkpoints)");
    const hasOldSchema = tableInfo.some(col => col.name === 'last_inode');
    const hasNewSchema = tableInfo.some(col => col.name === 'inode' && col.pk === 1);

    if (hasOldSchema && !hasNewSchema) {
        await db.exec(`
            CREATE TABLE checkpoints_new (
                inode TEXT PRIMARY KEY,
                file_path TEXT,
                last_offset INTEGER,
                generation INTEGER DEFAULT 1,
                completed INTEGER DEFAULT 0,
                file_size INTEGER DEFAULT 0,
                mtime_ms REAL DEFAULT 0,
                ctime_ms REAL DEFAULT 0,
                fingerprint TEXT
            );
            INSERT INTO checkpoints_new (inode, file_path, last_offset, generation, completed, file_size, mtime_ms, ctime_ms, fingerprint)
            SELECT CAST(last_inode AS TEXT), file_path, last_offset, 1, 0, 0, 0, 0, NULL FROM checkpoints WHERE last_inode IS NOT NULL;
            DROP TABLE checkpoints;
            ALTER TABLE checkpoints_new RENAME TO checkpoints;
        `);
    } else {
        await db.exec(`
            CREATE TABLE IF NOT EXISTS checkpoints (
                inode TEXT PRIMARY KEY,
                file_path TEXT,
                last_offset INTEGER,
                generation INTEGER DEFAULT 1,
                completed INTEGER DEFAULT 0,
                file_size INTEGER DEFAULT 0,
                mtime_ms REAL DEFAULT 0,
                ctime_ms REAL DEFAULT 0,
                fingerprint TEXT
            );
        `);
    }

    const checkpointColumns = await db.all("PRAGMA table_info(checkpoints)");
    const checkpointColumnNames = new Set(checkpointColumns.map(col => col.name));
    const checkpointColumnDefs = {
        file_size: 'INTEGER DEFAULT 0',
        mtime_ms: 'REAL DEFAULT 0',
        ctime_ms: 'REAL DEFAULT 0',
        fingerprint: 'TEXT'
    };
    for (const [column, definition] of Object.entries(checkpointColumnDefs)) {
        if (!checkpointColumnNames.has(column)) {
            await db.exec(`ALTER TABLE checkpoints ADD COLUMN ${column} ${definition}`);
        }
    }

    console.log("Migrations applied successfully.");
    return db;
}

if (require.main === module) {
    migrate().catch(console.error);
}

async function closeDb() {
    if (sharedDb) {
        await sharedDb.close();
        sharedDb = null;
    }
}

module.exports = { getDb, migrate, closeDb };
