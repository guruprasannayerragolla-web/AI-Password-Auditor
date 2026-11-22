-- =========================================================================
-- AI Password Auditor: PostgreSQL Normalized Schema (3NF)
-- Designed for enterprise and research-grade security audit logging.
-- =========================================================================

-- Enable UUID extension for secure, non-sequential identifiers
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Define Custom Enum Types
CREATE TYPE user_role AS ENUM ('SYSTEM_ADMIN', 'SECURITY_AUDITOR', 'END_USER');
CREATE TYPE risk_level AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SECURE');
CREATE TYPE audit_mode AS ENUM ('BASIC', 'ADVANCED', 'ENTERPRISE');

-- 1. Users Table
CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- Application admin portal access
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    organization_name VARCHAR(100),
    role user_role DEFAULT 'END_USER' NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 2. Organization Security Policies
CREATE TABLE security_policies (
    policy_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_name VARCHAR(100) NOT NULL,
    min_length INT DEFAULT 8 NOT NULL,
    min_entropy NUMERIC(5,2) DEFAULT 40.0 NOT NULL,
    require_uppercase BOOLEAN DEFAULT TRUE NOT NULL,
    require_lowercase BOOLEAN DEFAULT TRUE NOT NULL,
    require_digits BOOLEAN DEFAULT TRUE NOT NULL,
    require_special_char BOOLEAN DEFAULT TRUE NOT NULL,
    ban_personal_info BOOLEAN DEFAULT TRUE NOT NULL,
    ban_common_passwords BOOLEAN DEFAULT TRUE NOT NULL,
    created_by UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 3. Password Audit Logs Table (Main transaction record)
CREATE TABLE password_audit_logs (
    audit_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    mode audit_mode DEFAULT 'BASIC' NOT NULL,
    target_username VARCHAR(100), -- Subject checked (input field)
    target_email VARCHAR(150),    -- Subject checked (input field)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 4. Password Metrics Table (1-to-1 relationship with Audit Log for main outputs)
CREATE TABLE password_metrics (
    metric_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID UNIQUE NOT NULL REFERENCES password_audit_logs(audit_id) ON DELETE CASCADE,
    security_score INT CHECK (security_score BETWEEN 0 AND 100) NOT NULL,
    entropy_score NUMERIC(5,2) NOT NULL,
    effective_entropy NUMERIC(5,2) NOT NULL,
    risk_prediction risk_level NOT NULL,
    confidence_score NUMERIC(4,3) NOT NULL,
    crack_time_seconds NUMERIC(38, 2) NOT NULL,
    crack_time_formatted VARCHAR(100) NOT NULL,
    xai_explanation TEXT NOT NULL
);

-- 5. Detected Patterns Table (1-to-many relationship: Details patterns found in password)
CREATE TABLE detected_patterns (
    pattern_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID NOT NULL REFERENCES password_audit_logs(audit_id) ON DELETE CASCADE,
    pattern_type VARCHAR(50) NOT NULL, -- e.g., 'KEYBOARD_WALK', 'SEQUENCE', 'REPEATED_CHAR', 'LEET_SUBSTITUTION'
    pattern_value VARCHAR(100) NOT NULL, -- e.g., 'qwerty', '12345', 'aaa', 'p@$$'
    start_index INT NOT NULL,
    end_index INT NOT NULL,
    severity VARCHAR(20) NOT NULL -- 'HIGH', 'MEDIUM', 'LOW'
);

-- 6. Personal Info Exposure Table (1-to-many relationship: Identifies exact exposures)
CREATE TABLE personal_info_exposures (
    exposure_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID NOT NULL REFERENCES password_audit_logs(audit_id) ON DELETE CASCADE,
    field_exposed VARCHAR(50) NOT NULL, -- 'FIRST_NAME', 'LAST_NAME', 'EMAIL', 'USERNAME', 'ORGANIZATION'
    matched_substring VARCHAR(100) NOT NULL,
    match_type VARCHAR(30) NOT NULL -- 'EXACT', 'SUBSTRING', 'LEET_MUTATION'
);

-- 7. Recommendations Table (1-to-many relationship)
CREATE TABLE audit_recommendations (
    recommendation_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID NOT NULL REFERENCES password_audit_logs(audit_id) ON DELETE CASCADE,
    recommendation_code VARCHAR(30) NOT NULL, -- 'INCREASE_LENGTH', 'REMOVE_KEYBOARD_WALK', etc.
    recommendation_text TEXT NOT NULL,
    priority VARCHAR(10) NOT NULL -- 'HIGH', 'MEDIUM', 'LOW'
);

-- 8. Comparison Lab Sessions (Tracks groups of passwords compared together)
CREATE TABLE comparison_sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 9. Comparison Members Table
CREATE TABLE comparison_members (
    member_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES comparison_sessions(session_id) ON DELETE CASCADE,
    label VARCHAR(50) NOT NULL, -- e.g., 'Old Password', 'Work Passphrase'
    security_score INT NOT NULL,
    entropy_score NUMERIC(5,2) NOT NULL,
    crack_time_formatted VARCHAR(100) NOT NULL,
    risk_level risk_level NOT NULL
);

-- =========================================================================
-- INDEXES FOR HIGH-PERFORMANCE SEARCHING & REPORTING
-- =========================================================================
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_audit_logs_user ON password_audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON password_audit_logs(created_at);
CREATE INDEX idx_password_metrics_score ON password_metrics(security_score);
CREATE INDEX idx_password_metrics_risk ON password_metrics(risk_prediction);
CREATE INDEX idx_detected_patterns_audit ON detected_patterns(audit_id);
CREATE INDEX idx_personal_info_exposure_audit ON personal_info_exposures(audit_id);

-- =========================================================================
-- TRIGGERS FOR AUTO-UPDATING 'updated_at' TIMESTAMP
-- =========================================================================
CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_modtime
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();
