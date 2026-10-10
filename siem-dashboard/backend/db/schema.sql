CREATE TABLE attackers (
    source_ip VARCHAR(45) PRIMARY KEY,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    threat_score INTEGER DEFAULT 0,
    risk_level VARCHAR(20) DEFAULT 'LOW'
);

CREATE TABLE sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    source_ip VARCHAR(45) REFERENCES attackers(source_ip),
    start_time TIMESTAMP WITH TIME ZONE,
    end_time TIMESTAMP WITH TIME ZONE,
    duration INTEGER,
    threat_score INTEGER DEFAULT 0
);

CREATE TABLE events (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) REFERENCES sessions(session_id),
    event_type VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    raw_data JSONB NOT NULL
);

CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) REFERENCES sessions(session_id),
    source_ip VARCHAR(45) REFERENCES attackers(source_ip),
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'OPEN',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
