"""
Database Configuration and Setup
PostgreSQL schema and initial migration
"""

# Database Schema SQL for PostgreSQL
DATABASE_SCHEMA = """
-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(120),
    department VARCHAR(80),
    role VARCHAR(50) DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    CONSTRAINT valid_role CHECK (role IN ('user', 'admin', 'manager'))
);

-- Knowledge base table
CREATE TABLE IF NOT EXISTS knowledge_base (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    document_type VARCHAR(50),
    content TEXT NOT NULL,
    file_path VARCHAR(500),
    section VARCHAR(100),
    version VARCHAR(20),
    status VARCHAR(20) DEFAULT 'active',
    tags JSONB,
    metadata JSONB,
    search_vector TSVECTOR,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id),
    CONSTRAINT valid_status CHECK (status IN ('active', 'archived', 'draft'))
);

-- Create full-text search index
CREATE INDEX IF NOT EXISTS idx_kb_search ON knowledge_base USING GIN(search_vector);
CREATE INDEX IF NOT EXISTS idx_kb_title ON knowledge_base USING GIN(title gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_kb_content ON knowledge_base USING GIN(content gin_trgm_ops);

-- Trigger to update search_vector
CREATE OR REPLACE FUNCTION update_search_vector()
RETURNS TRIGGER AS $$
BEGIN
    NEW.search_vector := 
        setweight(to_tsvector('english', COALESCE(NEW.title, '')), 'A') ||
        setweight(to_tsvector('english', COALESCE(NEW.content, '')), 'B') ||
        setweight(to_tsvector('english', COALESCE(NEW.section, '')), 'C');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trig_update_kb_search_vector
    BEFORE INSERT OR UPDATE ON knowledge_base
    FOR EACH ROW
    EXECUTE FUNCTION update_search_vector();

-- Compliance rules table
CREATE TABLE IF NOT EXISTS compliance_rules (
    id SERIAL PRIMARY KEY,
    rule_type VARCHAR(50) NOT NULL,
    target VARCHAR(255) NOT NULL,
    reason TEXT,
    severity VARCHAR(20) DEFAULT 'high',
    alternative_suggestions JSONB,
    source_document VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_rule_type CHECK (rule_type IN ('banned_subreddit', 'prohibited_account', 'restricted_content', 'keyword_filter')),
    CONSTRAINT valid_severity CHECK (severity IN ('low', 'medium', 'high', 'critical'))
);

CREATE INDEX IF NOT EXISTS idx_compliance_target ON compliance_rules(target);
CREATE INDEX IF NOT EXISTS idx_compliance_type ON compliance_rules(rule_type);

-- Conversations table
CREATE TABLE IF NOT EXISTS conversations (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255),
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_conv_user ON conversations(user_id);
CREATE INDEX IF NOT EXISTS idx_conv_activity ON conversations(last_activity DESC);

-- Messages table
CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL,
    content TEXT NOT NULL,
    sources JSONB,
    compliance_checks JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processing_time FLOAT,
    CONSTRAINT valid_role CHECK (role IN ('user', 'assistant', 'system'))
);

CREATE INDEX IF NOT EXISTS idx_msg_conversation ON messages(conversation_id);
CREATE INDEX IF NOT EXISTS idx_msg_timestamp ON messages(timestamp DESC);

-- Query analytics table
CREATE TABLE IF NOT EXISTS queries (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    query_text TEXT NOT NULL,
    query_type VARCHAR(50),
    intent VARCHAR(100),
    results_count INTEGER,
    sources_used JSONB,
    compliance_triggered BOOLEAN DEFAULT FALSE,
    response_time FLOAT,
    success BOOLEAN DEFAULT TRUE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_query_user ON queries(user_id);
CREATE INDEX IF NOT EXISTS idx_query_timestamp ON queries(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_query_type ON queries(query_type);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INTEGER,
    details JSONB,
    ip_address VARCHAR(50),
    user_agent VARCHAR(255),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);

-- Insert default admin user (password: admin123)
INSERT INTO users (username, email, password_hash, full_name, department, role)
VALUES (
    'admin',
    'admin@secureassist.local',
    'pbkdf2:sha256:600000$' || encode(gen_random_bytes(16), 'hex') || '$' || encode(gen_random_bytes(32), 'hex'),
    'System Administrator',
    'IT',
    'admin'
) ON CONFLICT (username) DO NOTHING;

-- Insert sample compliance rules
INSERT INTO compliance_rules (rule_type, target, reason, severity, alternative_suggestions, source_document)
VALUES
    ('banned_subreddit', 'r/wallstreetbets', 'High-risk community with volatile and promotional content', 'high', '["r/stocks", "r/investing"]'::jsonb, 'SOP-REDDIT-042'),
    ('banned_subreddit', 'r/pennystocks', 'High manipulation risk and pump-and-dump schemes', 'critical', '["r/stocks", "r/investing"]'::jsonb, 'SOP-REDDIT-042'),
    ('prohibited_account', '@scam_alerts', 'Known fraudulent account', 'critical', '[]'::jsonb, 'SOP-SOCIAL-SECURITY-2024'),
    ('restricted_content', 'cryptocurrency promotion', 'Requires special approval per compliance policy', 'medium', '["r/CryptoMarkets"]'::jsonb, 'SOP-CRYPTO-2024')
ON CONFLICT DO NOTHING;

-- Insert sample knowledge base documents
INSERT INTO knowledge_base (title, document_type, content, section, version, tags, created_by)
SELECT 
    'Reddit Posting Guidelines - SOP-REDDIT-2024',
    'SOP',
    'Standard Operating Procedure for Reddit Content Posting

1. OVERVIEW
This document outlines the approved guidelines for posting content on Reddit as a representative of our organization.

2. PROHIBITED SUBREDDITS
The following subreddits are strictly prohibited for company-related content:
- r/wallstreetbets (high-risk, volatile community)
- r/pennystocks (manipulation risk)
- r/cryptocurrency (for promotional content)

3. APPROVED SUBREDDITS
The following subreddits are approved for content posting:
- r/stocks (financial discussions)
- r/investing (long-term investment discussions)
- r/technology (tech-related content)

4. CONTENT GUIDELINES
- Always disclose company affiliation
- Follow subreddit rules strictly
- Avoid promotional language
- Respond to negative comments within 2 hours
- Escalate threats or serious violations immediately

5. APPROVAL PROCESS
All posts must be reviewed by the social media team before submission.',
    '3.2',
    '2024.1',
    '["reddit", "social-media", "guidelines", "sop"]'::jsonb,
    1
FROM users WHERE username = 'admin' LIMIT 1
ON CONFLICT DO NOTHING;

-- Create materialized view for analytics
CREATE MATERIALIZED VIEW IF NOT EXISTS query_analytics AS
SELECT 
    DATE_TRUNC('day', timestamp) as date,
    query_type,
    COUNT(*) as query_count,
    AVG(response_time) as avg_response_time,
    COUNT(*) FILTER (WHERE compliance_triggered = TRUE) as compliance_checks
FROM queries
GROUP BY DATE_TRUNC('day', timestamp), query_type;

CREATE INDEX IF NOT EXISTS idx_query_analytics_date ON query_analytics(date DESC);

-- Function to refresh analytics
CREATE OR REPLACE FUNCTION refresh_analytics()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY query_analytics;
END;
$$ LANGUAGE plpgsql;

-- Comments for documentation
COMMENT ON TABLE users IS 'User accounts with authentication and role-based access control';
COMMENT ON TABLE knowledge_base IS 'Internal knowledge repository including SOPs, policies, and guidelines';
COMMENT ON TABLE compliance_rules IS 'Hard-coded compliance rules for content validation';
COMMENT ON TABLE conversations IS 'User conversation sessions with the AI assistant';
COMMENT ON TABLE messages IS 'Individual messages within conversations';
COMMENT ON TABLE queries IS 'Query analytics for performance tracking';
COMMENT ON TABLE audit_logs IS 'Audit trail for all system activities';
"""

# MongoDB Schema (Alternative/Supplementary for document storage)
MONGODB_SCHEMA = """
// Users Collection
db.createCollection("users", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["username", "email", "password_hash"],
            properties: {
                username: { bsonType: "string" },
                email: { bsonType: "string" },
                password_hash: { bsonType: "string" },
                full_name: { bsonType: "string" },
                department: { bsonType: "string" },
                role: { enum: ["user", "admin", "manager"] },
                is_active: { bsonType: "bool" },
                created_at: { bsonType: "date" },
                last_login: { bsonType: "date" }
            }
        }
    }
});

db.users.createIndex({ username: 1 }, { unique: true });
db.users.createIndex({ email: 1 }, { unique: true });

// Knowledge Base Collection
db.createCollection("knowledge_base", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["title", "content"],
            properties: {
                title: { bsonType: "string" },
                document_type: { bsonType: "string" },
                content: { bsonType: "string" },
                file_path: { bsonType: "string" },
                section: { bsonType: "string" },
                version: { bsonType: "string" },
                status: { enum: ["active", "archived", "draft"] },
                tags: { bsonType: "array" },
                metadata: { bsonType: "object" },
                created_at: { bsonType: "date" },
                updated_at: { bsonType: "date" },
                created_by: { bsonType: "string" }
            }
        }
    }
});

db.knowledge_base.createIndex({ title: "text", content: "text" });
db.knowledge_base.createIndex({ document_type: 1 });
db.knowledge_base.createIndex({ status: 1 });

// Compliance Rules Collection
db.createCollection("compliance_rules");
db.compliance_rules.createIndex({ rule_type: 1 });
db.compliance_rules.createIndex({ target: 1 });

// Conversations Collection
db.createCollection("conversations");
db.conversations.createIndex({ user_id: 1 });
db.conversations.createIndex({ last_activity: -1 });

// Messages Collection
db.createCollection("messages");
db.messages.createIndex({ conversation_id: 1 });
db.messages.createIndex({ timestamp: -1 });

// Queries Collection
db.createCollection("queries");
db.queries.createIndex({ user_id: 1 });
db.queries.createIndex({ timestamp: -1 });
db.queries.createIndex({ query_type: 1 });
"""

if __name__ == '__main__':
    print("Database schema ready for initialization")
    print("PostgreSQL Schema:")
    print(DATABASE_SCHEMA)
