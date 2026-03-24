-- ATHENA Database Tables

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'analyst',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    event_uid VARCHAR(64) UNIQUE NOT NULL,
    event_name VARCHAR(255),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    event_type VARCHAR(100),
    tactic VARCHAR(100),
    technique_id VARCHAR(64),
    severity VARCHAR(20),
    is_malicious BOOLEAN DEFAULT FALSE,
    tactic_encoded INTEGER,
    severity_encoded INTEGER,
    mcdm_score FLOAT,
    threat_actor VARCHAR(100),
    threat_feed_hit BOOLEAN DEFAULT FALSE,
    raw_data JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attack_scenarios (
    id SERIAL PRIMARY KEY,
    scenario_name VARCHAR(255) NOT NULL,
    mitre_tactic VARCHAR(100),
    mitre_technique VARCHAR(100),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detection_results (
    id SERIAL PRIMARY KEY,
    event_id INTEGER REFERENCES events(id) ON DELETE CASCADE,
    model_name VARCHAR(100),
    confidence_score FLOAT,
    anomaly_score FLOAT,
    detected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    is_true_positive BOOLEAN,
    is_malicious_pred BOOLEAN,
    raw_data JSONB
);

CREATE TABLE IF NOT EXISTS correlations (
    id SERIAL PRIMARY KEY,
    chain_id VARCHAR(100),
    parent_event_id INTEGER REFERENCES events(id) ON DELETE CASCADE,
    child_event_id INTEGER REFERENCES events(id) ON DELETE CASCADE,
    correlation_type VARCHAR(100),
    strength FLOAT,
    gap_seconds FLOAT,
    chain_score FLOAT,
    is_multi_stage BOOLEAN,
    reasons JSONB,
    raw_data JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
