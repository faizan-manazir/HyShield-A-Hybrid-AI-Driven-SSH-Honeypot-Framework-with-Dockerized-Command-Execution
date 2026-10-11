const fs = require('fs');
const path = require('path');
const { getDb } = require('../db/migrate');
const crypto = require('crypto');
const correlation = require('./correlation');

// Event uniqueness is now determined by file path and byte offset

class IngestionService {
    constructor(logFilePath) {
        this.logFilePath = logFilePath;
        this.fd = null;
        this.offset = 0;
        this.inode = 0;
        this.generation = 1;
        this.fileSize = 0;
        this.mtimeMs = 0;
        this.ctimeMs = 0;
        this.fingerprint = null;
        this.watcher = null;
        this.rewatchTimer = null;
        this.watchRetryTimer = null;
        this.watchRetryIntervalMs = 5000;
        this.stopped = false;
        this.db = null;
        this.isProcessing = false;
        
        // Metrics
        this.metrics = {
            eventsIngested: 0,
            errors: 0,
            lastIngestTime: null,
            lagMs: 0
        };
    }

    async init() {
        this.db = await getDb();
        await this.recoverRotatedFiles();
        await this.loadCheckpoint();
        this.watchFile();
        console.log(`[Ingestion] Started tailing ${this.logFilePath} from offset ${this.offset}`);
        this.processNewData(); // Fire and forget initial catchup
    }

    async recoverRotatedFiles() {
        const rows = await this.db.all('SELECT * FROM checkpoints WHERE completed = 0');
        console.log(`[Ingestion] recoverRotatedFiles: found ${rows.length} uncompleted checkpoints`);
        for (const row of rows) {
            console.log(`[Ingestion] Checking checkpoint inode=${row.inode} offset=${row.last_offset}`);
            const dir = path.dirname(this.logFilePath);
            if (!fs.existsSync(dir)) continue;
            
            let fileFound = false;
            let success = false;
            
            const files = fs.readdirSync(dir);
            for (const f of files) {
                const fullPath = path.join(dir, f);
                try {
                    const st = fs.statSync(fullPath);
                    if (st.ino.toString() === row.inode.toString()) {
                        fileFound = true;
                        console.log(`[Ingestion] Found matching inode file: ${f}, size=${st.size}`);
                        if (st.size < row.last_offset) {
                            console.warn(`[Ingestion] Rotated file ${f} is shorter than checkpoint offset. File size=${st.size}, checkpoint offset=${row.last_offset}. Keeping checkpoint unresolved.`);
                        } else if (st.size === row.last_offset) {
                            success = await this.checkpointCoversFile(row.inode, st.size);
                            if (!success) {
                                console.warn(`[Ingestion] Checkpoint inode=${row.inode} does not match terminal offset ${st.size}. Keeping checkpoint unresolved.`);
                            }
                        } else {
                            console.log(`[Ingestion] Recovering unread records from rotated file: ${f}`);
                            this.fd = fs.openSync(fullPath, 'r');
                            try {
                                this.offset = row.last_offset;
                                this.inode = st.ino.toString();
                                this.generation = row.generation;
                                this.fileSize = row.file_size || 0;
                                this.mtimeMs = row.mtime_ms || 0;
                                this.ctimeMs = row.ctime_ms || 0;
                                this.fingerprint = row.fingerprint || null;

                                // Await full flush
                                const result = await this.processNewData();

                                const finalStats = fs.fstatSync(this.fd);
                                const checkpointCommitted = await this.checkpointCoversFile(row.inode, finalStats.size);
                                if (result.ok && result.checkpointCommitted && this.offset >= finalStats.size && checkpointCommitted) {
                                    success = true;
                                } else {
                                    console.warn(`[Ingestion] Recovery incomplete for ${f}. Expected offset ${finalStats.size}, got ${this.offset}`);
                                }
                            } finally {
                                // Recovery can fail after opening the rotated file (for example, if
                                // checkpoint verification fails). Never leak the descriptor.
                                this.closeFile();
                            }
                        }
                        break;
                    }
                } catch (e) {
                    console.warn(`[Ingestion] Could not inspect rotated-file candidate ${fullPath}:`, e.message);
                }
            }
            
            if (!fileFound) {
                console.warn(`[Ingestion] Could not find file for uncompleted checkpoint inode=${row.inode}. Keeping checkpoint unresolved.`);
            } else if (success) {
                await this.db.run('UPDATE checkpoints SET completed = 1 WHERE inode = ?', [row.inode]);
                console.log(`[Ingestion] Marked checkpoint inode=${row.inode} as completed.`);
            }
        }
    }

    async checkpointCoversFile(inode, fileSize) {
        const row = await this.db.get('SELECT last_offset FROM checkpoints WHERE inode = ?', [inode.toString()]);
        return !!row && row.last_offset >= fileSize;
    }

    async markCheckpointCompleteIfFullyProcessed(inode, fileSize, currentOffset) {
        if (!inode || fileSize === null || currentOffset < fileSize) return false;
        const checkpointCommitted = await this.checkpointCoversFile(inode, fileSize);
        if (!checkpointCommitted) return false;
        await this.db.run('UPDATE checkpoints SET completed = 1 WHERE inode = ?', [inode.toString()]);
        return true;
    }

    async loadCheckpoint() {
        if (!fs.existsSync(this.logFilePath)) {
             this.offset = 0;
             return;
        }
        const st = fs.statSync(this.logFilePath);
        this.inode = st.ino.toString();
        const row = await this.db.get('SELECT * FROM checkpoints WHERE inode = ?', [this.inode]);
        if (row) {
            this.offset = row.last_offset;
            this.generation = row.generation;
            this.fileSize = row.file_size || 0;
            this.mtimeMs = row.mtime_ms || 0;
            this.ctimeMs = row.ctime_ms || 0;
            this.fingerprint = row.fingerprint || null;
            console.log(`[Ingestion] Resuming from checkpoint: offset ${this.offset}`);
        } else {
            const maxGen = await this.db.get('SELECT MAX(generation) as maxg FROM checkpoints');
            this.generation = (maxGen && maxGen.maxg ? maxGen.maxg : 0) + 1;
            this.offset = 0;
            this.fileSize = st.size;
            this.mtimeMs = st.mtimeMs;
            this.ctimeMs = st.ctimeMs;
            this.fingerprint = null;
        }
    }

    async saveCheckpoint(stats) {
        await this.persistCheckpoint(stats, this.offset, 0);
    }

    sourceFingerprint(stats) {
        if (!this.fd || !stats || stats.size === 0) return null;
        const chunkSize = Math.min(4096, stats.size);
        const first = Buffer.alloc(chunkSize);
        fs.readSync(this.fd, first, 0, chunkSize, 0);

        if (stats.size <= chunkSize) {
            return crypto.createHash('sha256').update(first).digest('hex');
        }

        const last = Buffer.alloc(chunkSize);
        fs.readSync(this.fd, last, 0, chunkSize, stats.size - chunkSize);
        return crypto.createHash('sha256').update(first).update(last).digest('hex');
    }

    rememberSourceState(stats, offset, fingerprint) {
        this.fileSize = stats.size;
        this.mtimeMs = stats.mtimeMs;
        this.ctimeMs = stats.ctimeMs;
        this.fingerprint = fingerprint || null;
        this.offset = offset;
    }

    async persistCheckpoint(stats, offset, completed = 0) {
        const fingerprint = this.sourceFingerprint(stats);
        await this.db.run(`
            INSERT INTO checkpoints (inode, file_path, last_offset, generation, completed, file_size, mtime_ms, ctime_ms, fingerprint) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(inode) DO UPDATE SET 
            file_path = excluded.file_path,
            last_offset = excluded.last_offset,
            generation = excluded.generation,
            completed = excluded.completed,
            file_size = excluded.file_size,
            mtime_ms = excluded.mtime_ms,
            ctime_ms = excluded.ctime_ms,
            fingerprint = excluded.fingerprint
        `, [
            stats.ino.toString(),
            this.logFilePath,
            offset,
            this.generation,
            completed,
            stats.size,
            stats.mtimeMs,
            stats.ctimeMs,
            fingerprint
        ]);
        this.rememberSourceState(stats, offset, fingerprint);
    }

    watchFile() {
        this.stopped = false;
        if (!fs.existsSync(this.logFilePath)) {
            this.scheduleWatchRetry(`File ${this.logFilePath} does not exist yet. Waiting...`);
            return;
        }
        if (this.watchRetryTimer) {
            clearTimeout(this.watchRetryTimer);
            this.watchRetryTimer = null;
        }
        if (this.watcher) {
            this.watcher.close();
            this.watcher = null;
        }
        if (this.fd) {
            fs.closeSync(this.fd);
            this.fd = null;
        }

        let stats;
        try {
            // The file can disappear between existsSync() and stat/open during rotation.
            // Treat that race like a missing file and retry instead of crashing the watcher setup.
            stats = fs.statSync(this.logFilePath);
            this.fd = fs.openSync(this.logFilePath, 'r');
        } catch (error) {
            this.fd = null;
            this.scheduleWatchRetry(`Could not open ${this.logFilePath}: ${error.message}`);
            return;
        }
        
        // Detect rotation or truncation (new generation needed if we dropped data)
        if (this.inode && this.inode !== stats.ino.toString()) {
            console.log('[Ingestion] File rotated (inode changed). Resetting offset.');
            this.offset = 0;
            this.inode = stats.ino.toString();
            this.generation++;
        } else if (stats.size < this.offset) {
            console.log('[Ingestion] File truncated. Resetting offset.');
            this.offset = 0;
            this.generation++;
        } else {
            this.inode = stats.ino.toString();
        }

        try {
            this.watcher = fs.watch(this.logFilePath, (eventType) => {
                if (eventType === 'change') {
                    this.processNewData();
                } else if (eventType === 'rename') {
                    console.log('[Ingestion] File renamed/rotated. Re-watching...');
                    this.handleRenameEvent().catch(console.error);
                }
            });
            this.watcher.on('error', (error) => {
                console.warn(`[Ingestion] File watcher failed for ${this.logFilePath}: ${error.message}`);
                if (this.watcher) {
                    this.watcher.close();
                    this.watcher = null;
                }
                this.scheduleWatchRetry('Recovering from file watcher error');
            });
        } catch (error) {
            this.watcher = null;
            this.scheduleWatchRetry(`Could not watch ${this.logFilePath}: ${error.message}`);
        }
    }

    scheduleWatchRetry(reason) {
        console.warn(`[Ingestion] ${reason}`);
        if (this.stopped) return;
        if (this.watchRetryTimer) clearTimeout(this.watchRetryTimer);
        this.watchRetryTimer = setTimeout(() => {
            this.watchRetryTimer = null;
            if (!this.stopped) {
                this.watchFile();
                // The file may already contain data by the time watching resumes.
                // Catch up immediately instead of waiting for another fs.watch event.
                this.processNewData();
            }
        }, this.watchRetryIntervalMs);
    }

    async handleRenameEvent({ rewatch = true } = {}) {
        const rotatedInode = this.inode;
        let rotatedSize = null;
        try {
            const result = await this.processNewData();
            if (this.fd) {
                try {
                    rotatedSize = fs.fstatSync(this.fd).size;
                } catch (e) {
                    console.warn(`[Ingestion] Could not stat rotated file for inode=${rotatedInode}:`, e.message);
                }
            }

            const completed = result.ok && await this.markCheckpointCompleteIfFullyProcessed(rotatedInode, rotatedSize, this.offset);
            if (!completed && rotatedInode && rotatedSize !== null) {
                console.warn(`[Ingestion] Rename recovery incomplete for inode=${rotatedInode}. File size=${rotatedSize}, offset=${this.offset}. Keeping checkpoint unresolved.`);
            }
        } catch (e) {
            console.error('[Ingestion] Error handling rename event:', e);
        } finally {
            this.closeFile(false);
            if (rewatch && !this.stopped) {
                if (this.rewatchTimer) {
                    clearTimeout(this.rewatchTimer);
                }
                this.rewatchTimer = setTimeout(() => {
                    this.rewatchTimer = null;
                    if (!this.stopped) {
                        this.watchFile();
                        this.processNewData();
                    }
                }, 50);
            }
        }
    }

    closeFile(stop = true) {
        if (stop) {
            this.stopped = true;
            if (this.watchRetryTimer) {
                clearTimeout(this.watchRetryTimer);
                this.watchRetryTimer = null;
            }
            if (this.rewatchTimer) {
                clearTimeout(this.rewatchTimer);
                this.rewatchTimer = null;
            }
        }
        if (this.watcher) {
            this.watcher.close();
            this.watcher = null;
        }
        if (this.fd) {
            fs.closeSync(this.fd);
            this.fd = null;
        }
    }
    async processNewData() {
        if (!this.fd) return { ok: true, processed: false, checkpointCommitted: false };
        
        // Serialize concurrent trigger events
        while (this.isProcessing) {
            await new Promise(r => setTimeout(r, 20));
        }
        this.isProcessing = true;

        if (!this.fd) {
            this.isProcessing = false;
            return { ok: true, processed: false, checkpointCommitted: false };
        }

        try {
            const stats = fs.fstatSync(this.fd); // Use fstat to check the OPEN file
            const hasPriorSourceMetadata = this.fileSize > 0 && (this.mtimeMs > 0 || this.ctimeMs > 0);
            const sameSizeRewrite = hasPriorSourceMetadata &&
                stats.size === this.offset &&
                stats.size === this.fileSize &&
                stats.size > 0 &&
                (stats.mtimeMs !== this.mtimeMs || stats.ctimeMs !== this.ctimeMs);
            
            if (stats.size < this.offset || sameSizeRewrite) {
                console.log('[Ingestion] File truncated. Resetting offset.');
                this.offset = 0;
                this.generation++;
            }

            if (stats.size <= this.offset) {
                if (this.fileSize !== stats.size || this.mtimeMs !== stats.mtimeMs || this.ctimeMs !== stats.ctimeMs) {
                    await this.persistCheckpoint(stats, this.offset, 0);
                    return { ok: true, processed: false, checkpointCommitted: true };
                }
                return { ok: true, processed: false, checkpointCommitted: false };
            }

            const bytesToRead = stats.size - this.offset;
            const buf = Buffer.alloc(bytesToRead);
            const bytesRead = fs.readSync(this.fd, buf, 0, bytesToRead, this.offset);
            
            const chunk = buf.toString('utf8', 0, bytesRead);
            let lines = chunk.split('\n');
            lines.pop(); // The last element is either empty string (if chunk ended with \n) or an incomplete line. Either way, drop it for now.

            if (lines.length > 0) {
                const newOffset = this.offset + Buffer.byteLength(lines.join('\n') + '\n', 'utf8');
                await this.processLines(lines, stats, newOffset);
                this.offset = newOffset;
                return { ok: true, processed: true, checkpointCommitted: true };
            }

        } catch (e) {
            console.error('[Ingestion] Error processing data:', e);
            this.metrics.errors++;
            return { ok: false, processed: false, checkpointCommitted: false };
        } finally {
            this.isProcessing = false;
        }

        return { ok: true, processed: false, checkpointCommitted: false };
    }

    async processLines(lines, stats, newOffset) {
        await this.db.exec('BEGIN TRANSACTION');
        try {
            let currentOffset = newOffset - Buffer.byteLength(lines.join('\n') + '\n', 'utf8');
            for (const line of lines) {
                const lineByteLength = Buffer.byteLength(line + '\n', 'utf8');
                const startOffset = currentOffset;
                currentOffset += lineByteLength;

                if (!line.trim()) continue;
                
                let evt;
                try {
                    evt = JSON.parse(line);
                    // Cowrie records must be JSON objects. Valid JSON primitives such as
                    // null must be quarantined as malformed, not abort the whole batch.
                    if (!evt || typeof evt !== 'object' || Array.isArray(evt)) {
                        throw new Error('Cowrie event must be a JSON object');
                    }
                } catch (e) {
                    this.metrics.errors++;
                    const malformedId = crypto.createHash('md5').update(`${this.logFilePath}|${this.inode}|${this.generation}|${startOffset}|${line}`).digest('hex');
                    await this.db.run(`
                        INSERT OR IGNORE INTO raw_events (id, session_id, timestamp, eventid, payload)
                        VALUES (?, ?, ?, ?, ?)
                    `, [malformedId, 'malformed', new Date().toISOString(), 'error.malformed', JSON.stringify({ raw_line: line })]);
                    continue;
                }

                const eventId = crypto.createHash('md5').update(`${this.logFilePath}|${this.inode}|${this.generation}|${startOffset}|${line}`).digest('hex');
                
                await this.db.run(`
                    INSERT OR IGNORE INTO raw_events (id, session_id, timestamp, eventid, payload)
                    VALUES (?, ?, ?, ?, ?)
                `, [eventId, evt.session || null, evt.timestamp, evt.eventid, JSON.stringify(evt)]);

                if (evt.session) {
                    await this.db.run(`
                        INSERT INTO sessions (session_id, src_ip, start_time, end_time, is_closed)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(session_id) DO UPDATE SET
                        start_time = MIN(start_time, excluded.start_time),
                        end_time = MAX(end_time, excluded.end_time),
                        is_closed = excluded.is_closed OR is_closed
                    `, [evt.session, evt.src_ip, evt.timestamp, evt.timestamp, evt.eventid === 'cowrie.session.closed' ? 1 : 0]);
                    
                    await this.evaluateSession(evt.session);
                }

                this.metrics.eventsIngested++;
                this.metrics.lastIngestTime = new Date();
                this.metrics.lagMs = Date.now() - new Date(evt.timestamp).getTime();
            }
            
            // Advance checkpoint within the same transaction!
            const fingerprint = this.sourceFingerprint(stats);
            await this.db.run(`
                INSERT INTO checkpoints (inode, file_path, last_offset, generation, completed, file_size, mtime_ms, ctime_ms, fingerprint) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(inode) DO UPDATE SET 
                file_path = excluded.file_path,
                last_offset = excluded.last_offset,
                generation = excluded.generation,
                completed = excluded.completed,
                file_size = excluded.file_size,
                mtime_ms = excluded.mtime_ms,
                ctime_ms = excluded.ctime_ms,
                fingerprint = excluded.fingerprint
            `, [
                stats.ino.toString(),
                this.logFilePath,
                newOffset,
                this.generation,
                0,
                stats.size,
                stats.mtimeMs,
                stats.ctimeMs,
                fingerprint
            ]);
            
            await this.db.exec('COMMIT');
            this.rememberSourceState(stats, newOffset, fingerprint);
        } catch (e) {
            await this.db.exec('ROLLBACK');
            throw e;
        }
    }

    async evaluateSession(sessionId) {
        // Fetch all raw events for this session
        const rows = await this.db.all('SELECT payload FROM raw_events WHERE session_id = ? ORDER BY timestamp ASC', [sessionId]);
        const events = rows.map(r => JSON.parse(r.payload));
        
        const result = correlation.evaluateSessionEvents(events);
        
        await this.db.run(`
            UPDATE sessions SET 
                threat_score = ?, 
                risk_level = ?, 
                summary = ?
            WHERE session_id = ?
        `, [result.threatScore, result.riskLevel, JSON.stringify({ summary: result.summary, dimensions: result.dimensions, mitre: result.mitre, explanations: result.explanations }), sessionId]);

        for (const alert of result.alerts) {
            const alertId = crypto.createHash('md5').update(`${sessionId}|${alert.title}`).digest('hex');
            await this.db.run(`
                INSERT INTO alerts (id, session_id, severity, title, reason, mitre)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    severity = excluded.severity,
                    reason = excluded.reason,
                    mitre = excluded.mitre
                    -- Note: Intentionally NOT updating status to preserve analyst closure
            `, [alertId, sessionId, alert.severity, alert.title, alert.reason, alert.mitre]);
        }
    }
}

module.exports = IngestionService;
