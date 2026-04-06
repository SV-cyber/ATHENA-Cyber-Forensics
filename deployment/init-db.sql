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

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    alert_id VARCHAR(64) UNIQUE NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    source_ip INET,
    event_type VARCHAR(100),
    severity VARCHAR(20),
    rule_alerts JSONB,
    ml_score FLOAT,
    duplicate_count INTEGER DEFAULT 1,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT alerts_status_check CHECK (status IN ('active', 'acknowledged', 'resolved', 'throttled'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_alert_id ON alerts(alert_id);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);

CREATE TABLE IF NOT EXISTS scenario_executions (
    id SERIAL PRIMARY KEY,
    execution_id VARCHAR(64) UNIQUE NOT NULL,
    scenario_name VARCHAR(255) NOT NULL,
    started_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    events_generated INTEGER DEFAULT 0,
    status VARCHAR(32) DEFAULT 'running'
);
