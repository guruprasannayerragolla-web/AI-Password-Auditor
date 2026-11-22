import logging
import sqlite3
from typing import Generator
from .config import settings

logger = logging.getLogger(__name__)

# To make the codebase work immediately without database setup:
# We try to import psycopg2 to connect to PostgreSQL.
# If it fails or connection refuses, we print a warning and set up a simple SQLite database
# in the project workspace (backend/database.db) to act as a seamless fallback.

DB_CONNECTED = False
use_sqlite = True
sqlite_conn_path = "backend/database.db"

def init_db():
    global DB_CONNECTED, use_sqlite
    
    # Try PostgreSQL first
    try:
        import psycopg2
        # Check connection
        conn = psycopg2.connect(settings.DATABASE_URL, connect_timeout=2)
        conn.close()
        DB_CONNECTED = True
        use_sqlite = False
        logger.info("Successfully connected to PostgreSQL database.")
        print("[DATABASE] Connected to PostgreSQL successfully.")
        return
    except Exception as e:
        logger.warning(f"Could not connect to PostgreSQL ({e}). Falling back to SQLite database.")
        print(f"[DATABASE] PostgreSQL connection failed. Falling back to local SQLite at {sqlite_conn_path}.")
        use_sqlite = True
        
    # Set up SQLite tables if using SQLite
    try:
        conn = sqlite3.connect(sqlite_conn_path)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            organization_name TEXT,
            role TEXT DEFAULT 'END_USER',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Create password_audit_logs table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_audit_logs (
            audit_id TEXT PRIMARY KEY,
            user_id TEXT,
            mode TEXT DEFAULT 'BASIC',
            target_username TEXT,
            target_email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Create password_metrics table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_metrics (
            metric_id TEXT PRIMARY KEY,
            audit_id TEXT UNIQUE NOT NULL,
            security_score INTEGER,
            entropy_score REAL,
            effective_entropy REAL,
            risk_prediction TEXT,
            confidence_score REAL,
            crack_time_seconds REAL,
            crack_time_formatted TEXT,
            xai_explanation TEXT
        )
        """)
        
        # Create audit_recommendations table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_recommendations (
            recommendation_id TEXT PRIMARY KEY,
            audit_id TEXT NOT NULL,
            recommendation_code TEXT,
            recommendation_text TEXT,
            priority TEXT
        )
        """)
        
        # Create detected_patterns table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS detected_patterns (
            pattern_id TEXT PRIMARY KEY,
            audit_id TEXT NOT NULL,
            pattern_type TEXT,
            pattern_value TEXT,
            start_index INTEGER,
            end_index INTEGER,
            severity TEXT
        )
        """)
        
        conn.commit()
        conn.close()
        DB_CONNECTED = True
        logger.info("SQLite database tables verified/created successfully.")
    except Exception as sqle:
        logger.error(f"Failed to initialize SQLite fallback: {sqle}")
        DB_CONNECTED = False

# Run database setup check
init_db()

def get_db_connection():
    """
    Returns a database connection (SQLite or PostgreSQL) depending on the configuration.
    This provides a consistent interface to execute queries.
    """
    if use_sqlite:
        conn = sqlite3.connect(sqlite_conn_path)
        # Enable dictionary row access for matching PostgreSQL dictionaries
        conn.row_factory = sqlite3.Row
        return conn
    else:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(settings.DATABASE_URL)
        return conn
