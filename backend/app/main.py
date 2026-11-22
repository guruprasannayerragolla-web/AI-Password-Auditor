import time
import uuid
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, status, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import EmailStr

from .config import settings
from .models import AuditRequest, AuditResponse, CompareRequest, CompareResponse, CompareItem
from .database import get_db_connection, DB_CONNECTED, use_sqlite

# Import Core security engines
from .core.strength_engine import calculate_strength_and_complexity
from .core.entropy import analyze_entropy
from .core.patterns import detect_patterns
from .core.personal_info import analyze_personal_info_exposure
from .core.dictionary import check_dictionary_vulnerability
from .core.ml_predictor import predict_risk
from .core.attack_estimator import estimate_crack_resistance
from .core.xai_engine import generate_xai_explanation
from .core.recommender import generate_recommendations
from .core.reporter import export_as_json, export_as_csv, generate_pdf_report

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Intelligent AI-Powered Password Strength and Risk Assessment API",
    version="1.0.0"
)

# Configure CORS for frontend access (Vite, Next.js, or local HTML files)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Open for testing, restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CyberSecurity Rate Limiting (Token Bucket) ---
RATE_LIMIT_WINDOW = 60 # seconds
MAX_REQUESTS = 30
client_buckets: Dict[str, List[float]] = {}

def check_rate_limit(client_ip: str):
    """
    Implements a token bucket filter for security auditing endpoints.
    Allows 30 requests per minute.
    """
    now = time.time()
    if client_ip not in client_buckets:
        client_buckets[client_ip] = []
        
    # Clean old requests outside the window
    client_buckets[client_ip] = [t for t in client_buckets[client_ip] if now - t < RATE_LIMIT_WINDOW]
    
    if len(client_buckets[client_ip]) >= MAX_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Security policy restricts brute force audits to 30 requests per minute."
        )
    client_buckets[client_ip].append(now)

# --- Core Audit Logic Helper ---
def perform_audit(req: AuditRequest) -> Dict[str, Any]:
    """
    Orchestrates the entire security assessment sequence across all modules.
    """
    password = req.password
    
    # 1. Evaluate composition & basic strength
    strength_metrics = calculate_strength_and_complexity(password)
    composition = strength_metrics["composition"]
    
    # 2. Detect sequential patterns, keyboard walks, repetitions, dates
    patterns = detect_patterns(password)
    
    # 3. Simulate Dictionary Attack (RockYou patterns / common keys)
    dict_matched, dict_vuln_score, matched_term = check_dictionary_vulnerability(password)
    
    # 4. Check for personal information exposure
    pi_exposures = analyze_personal_info_exposure(
        password=password,
        username=req.username,
        email=req.email,
        first_name=req.first_name,
        last_name=req.last_name,
        organization=req.organization
    )
    
    # 5. Math Calculations: Shannon & Character Set Entropy
    entropy_metrics = analyze_entropy(
        password=password,
        alphabet_size=composition["alphabet_size"],
        pattern_count=len(patterns),
        dictionary_matched=dict_matched,
        personal_info_count=len(pi_exposures)
    )
    
    # 6. ML Risk Predictor (Random Forest / Fallback Expert System)
    ml_risk, ml_conf = predict_risk(
        password=password,
        composition=composition,
        entropy=entropy_metrics["effective_entropy"],
        pattern_count=len(patterns),
        dictionary_matched=dict_matched,
        personal_info_exposure_count=len(pi_exposures)
    )
    
    # Heuristically merge security score with ML findings
    # Adjust score if ML finds high risk or dictionary leaks
    final_score = strength_metrics["security_score"]
    if dict_matched:
        final_score = min(20, final_score)
    if len(pi_exposures) > 0:
        final_score = min(30, final_score)
    if ml_risk in ["CRITICAL", "HIGH"] and final_score > 50:
        final_score -= 20
        
    final_score = max(0, min(100, final_score))
    
    # Re-evaluate final risk level based on combined score
    if final_score < 30:
        risk_level = "CRITICAL"
        classification = "Highly Vulnerable"
    elif final_score < 50:
        risk_level = "HIGH"
        classification = "Weak Casing / Length"
    elif final_score < 70:
        risk_level = "MEDIUM"
        classification = "Moderate Strength"
    elif final_score < 85:
        risk_level = "LOW"
        classification = "Strong Protection"
    else:
        risk_level = "SECURE"
        classification = "Cryptographically Protected"
        
    # 7. GPU Hashing / AI Cracking estimation
    attack_metrics = estimate_crack_resistance(
        password=password,
        alphabet_size=composition["alphabet_size"],
        entropy=entropy_metrics["effective_entropy"],
        pattern_count=len(patterns),
        dictionary_matched=dict_matched
    )
    
    # 8. Explainable AI description
    xai_explanation = generate_xai_explanation(
        password=password,
        security_score=final_score,
        entropy=entropy_metrics["effective_entropy"],
        patterns=patterns,
        dictionary_matched=dict_matched,
        matched_dictionary_term=matched_term,
        personal_info_exposures=pi_exposures,
        risk_level=risk_level
    )
    
    # 9. Smart Recommendations checklist
    recommendations = generate_recommendations(
        password=password,
        security_score=final_score,
        entropy=entropy_metrics["effective_entropy"],
        patterns=patterns,
        dictionary_matched=dict_matched,
        personal_info_exposures=pi_exposures,
        composition=composition
    )
    
    # Compiled audit output
    audit_data = {
        "security_score": final_score,
        "entropy_score": entropy_metrics["character_set_entropy"],
        "effective_entropy": entropy_metrics["effective_entropy"],
        "risk_level": risk_level,
        "classification": classification,
        "dictionary_matched": dict_matched,
        "patterns_detected": patterns,
        "personal_info_exposed": pi_exposures,
        "crack_time_seconds": attack_metrics["realistic_crack_time_seconds"],
        "crack_time_formatted": attack_metrics["realistic_crack_time_formatted"],
        "ml_risk_prediction": ml_risk,
        "ml_confidence": ml_conf,
        "xai_explanation": xai_explanation,
        "recommendations": recommendations
    }
    
    # 10. Persist log to SQL Database (PostgreSQL or SQLite fallback)
    try:
        persist_audit_log(req, audit_data)
    except Exception as dbe:
        # Prevent DB errors from crashing the audit API response
        print(f"[DATABASE ERROR] Log write failed: {dbe}")
        
    return audit_data

def persist_audit_log(req: AuditRequest, res: Dict[str, Any]):
    """
    Writes structural audit and metric information to database tables.
    Handles SQL queries for both PostgreSQL and SQLite fallback.
    """
    if not DB_CONNECTED:
        return
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create audit session ID
    audit_id = str(uuid.uuid4())
    
    # Insert main log
    if use_sqlite:
        cursor.execute(
            "INSERT INTO password_audit_logs (audit_id, user_id, mode, target_username, target_email) VALUES (?, ?, ?, ?, ?)",
            (audit_id, None, req.mode.value, req.username, req.email)
        )
        # Metrics
        metric_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO password_metrics (metric_id, audit_id, security_score, entropy_score, effective_entropy, risk_prediction, confidence_score, crack_time_seconds, crack_time_formatted, xai_explanation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (metric_id, audit_id, res["security_score"], res["entropy_score"], res["effective_entropy"], res["risk_level"], res["ml_confidence"], res["crack_time_seconds"], res["crack_time_formatted"], res["xai_explanation"])
        )
        # Recommendations
        for r in res["recommendations"]:
            rec_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO audit_recommendations (recommendation_id, audit_id, recommendation_code, recommendation_text, priority) VALUES (?, ?, ?, ?, ?)",
                (rec_id, audit_id, r["recommendation_code"], r["recommendation_text"], r["priority"])
            )
        # Patterns
        for p in res["patterns_detected"]:
            pat_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO detected_patterns (pattern_id, audit_id, pattern_type, pattern_value, start_index, end_index, severity) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (pat_id, audit_id, p["pattern_type"], p["pattern_value"], p["start_index"], p["end_index"], p["severity"])
            )
    else: # PostgreSQL
        cursor.execute(
            "INSERT INTO password_audit_logs (audit_id, user_id, mode, target_username, target_email) VALUES (%s, %s, %s, %s, %s)",
            (audit_id, None, req.mode.value, req.username, req.email)
        )
        metric_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO password_metrics (metric_id, audit_id, security_score, entropy_score, effective_entropy, risk_prediction, confidence_score, crack_time_seconds, crack_time_formatted, xai_explanation) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (metric_id, audit_id, res["security_score"], res["entropy_score"], res["effective_entropy"], res["risk_level"], res["ml_confidence"], res["crack_time_seconds"], res["crack_time_formatted"], res["xai_explanation"])
        )
        for r in res["recommendations"]:
            rec_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO audit_recommendations (recommendation_id, audit_id, recommendation_code, recommendation_text, priority) VALUES (%s, %s, %s, %s, %s)",
                (rec_id, audit_id, r["recommendation_code"], r["recommendation_text"], r["priority"])
            )
        for p in res["patterns_detected"]:
            pat_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO detected_patterns (pattern_id, audit_id, pattern_type, pattern_value, start_index, end_index, severity) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (pat_id, audit_id, p["pattern_type"], p["pattern_value"], p["start_index"], p["end_index"], p["severity"])
            )
            
    conn.commit()
    conn.close()

# --- REST ENDPOINTS ---

@app.post("/api/v1/audit", response_model=AuditResponse, summary="Audits a single password")
def audit_password_endpoint(req: AuditRequest):
    """
    Main API endpoint to analyze a password and predict cybersecurity risks.
    """
    # Simple self-rate check for documentation purposes, using mock ip client loop
    check_rate_limit("localhost")
    return perform_audit(req)

@app.post("/api/v1/compare", response_model=CompareResponse, summary="Compare multiple passwords side-by-side")
def compare_passwords_endpoint(req: CompareRequest):
    """
    Allows user to audit and rank up to 10 passwords simultaneously in the comparison lab.
    """
    comparisons = []
    for idx, pwd in enumerate(req.passwords):
        # Create virtual request per password
        sub_req = AuditRequest(
            password=pwd,
            username=req.username,
            email=req.email,
            first_name=req.first_name,
            last_name=req.last_name,
            organization=req.organization,
            mode=AuditMode.ADVANCED
        )
        res = perform_audit(sub_req)
        
        comparisons.append({
            "password": pwd,
            "security_score": res["security_score"],
            "entropy_score": res["effective_entropy"],
            "risk_level": res["risk_level"],
            "crack_time_formatted": res["crack_time_formatted"],
            "rank": 0 # filled below
        })
        
    # Sort comparisons: highest score first, breaking ties with entropy
    comparisons.sort(key=lambda x: (-x["security_score"], -x["entropy_score"]))
    
    # Assign rank (1 is best)
    for rank_idx, item in enumerate(comparisons):
        item["rank"] = rank_idx + 1
        
    return {"comparisons": comparisons}

@app.get("/api/v1/export/pdf", summary="Generates a printable PDF report for download")
def export_pdf_endpoint(
    password: str = Query(..., description="Password to analyze"),
    username: str = Query(None),
    email: str = Query(None),
    first_name: str = Query(None),
    last_name: str = Query(None),
    organization: str = Query(None)
):
    """
    Computes an audit on the fly and returns a dynamic PDF download file directly.
    """
    req = AuditRequest(
        password=password,
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        organization=organization
    )
    audit_data = perform_audit(req)
    
    try:
        pdf_buffer = generate_pdf_report(audit_data)
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=AI_Password_Audit_Report.pdf"}
        )
    except ImportError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate PDF: {e}"
        )

@app.get("/api/v1/export/csv", summary="Generates a spreadsheet CSV report")
def export_csv_endpoint(
    password: str = Query(..., description="Password to analyze"),
    username: str = Query(None),
    email: str = Query(None),
    first_name: str = Query(None),
    last_name: str = Query(None),
    organization: str = Query(None)
):
    req = AuditRequest(
        password=password,
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        organization=organization
    )
    audit_data = perform_audit(req)
    csv_str = export_as_csv(audit_data)
    
    # Return string as streaming file responses
    buffer = BytesIO(csv_str.encode('utf-8'))
    return StreamingResponse(
        buffer,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=AI_Password_Audit.csv"}
    )

@app.get("/api/v1/health", summary="Basic service health check")
def health_endpoint():
    return {
        "status": "online",
        "database_connected": DB_CONNECTED,
        "database_engine": "SQLite Fallback" if use_sqlite else "PostgreSQL Server",
        "ml_models_loaded": True
    }
