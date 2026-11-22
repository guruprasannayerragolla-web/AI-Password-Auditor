from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
from enum import Enum

class AuditMode(str, Enum):
    BASIC = "BASIC"
    ADVANCED = "ADVANCED"
    ENTERPRISE = "ENTERPRISE"

class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SECURE = "SECURE"

class AuditRequest(BaseModel):
    password: str = Field(..., min_length=1, description="The password to audit")
    username: Optional[str] = Field(None, description="Username to check for personal data exposure")
    email: Optional[str] = Field(None, description="Email address to check for personal data exposure")
    first_name: Optional[str] = Field(None, description="First name of user")
    last_name: Optional[str] = Field(None, description="Last name of user")
    organization: Optional[str] = Field(None, description="Organization name")
    mode: AuditMode = Field(AuditMode.BASIC, description="Audit depth level")

    model_config = {
        "json_schema_extra": {
            "example": {
                "password": "AdminPass123!_john",
                "username": "johndoe",
                "email": "john.doe@acme.org",
                "first_name": "John",
                "last_name": "Doe",
                "organization": "Acme Corp",
                "mode": "ADVANCED"
            }
        }
    }

class PatternDetail(BaseModel):
    pattern_type: str = Field(..., description="E.g., KEYBOARD_WALK, SEQUENCE, REPEATED")
    pattern_value: str = Field(..., description="The matching substring")
    start_index: int
    end_index: int
    severity: str

class PersonalInfoExposure(BaseModel):
    field_exposed: str = Field(..., description="E.g. FIRST_NAME, EMAIL")
    matched_substring: str
    match_type: str = Field(..., description="EXACT, SUBSTRING, or LEET_MUTATION")

class RecommendationItem(BaseModel):
    recommendation_code: str
    recommendation_text: str
    priority: str

class AuditResponse(BaseModel):
    security_score: int = Field(..., description="Overall security rating from 0 (very weak) to 100 (exceptionally secure)")
    entropy_score: float = Field(..., description="Shannon entropy in bits")
    effective_entropy: float = Field(..., description="Modified entropy accounting for dictionary matches and pattern repetitions")
    risk_level: RiskLevel = Field(..., description="Classification level from CRITICAL to SECURE")
    classification: str = Field(..., description="Text description of security posture")
    dictionary_matched: bool = Field(..., description="True if password contains a dictionary word or RockYou pattern")
    patterns_detected: List[PatternDetail]
    personal_info_exposed: List[PersonalInfoExposure]
    crack_time_seconds: float
    crack_time_formatted: str
    ml_risk_prediction: RiskLevel
    ml_confidence: float
    xai_explanation: str
    recommendations: List[RecommendationItem]

class CompareRequest(BaseModel):
    passwords: List[str] = Field(..., min_items=1, max_items=10)
    username: Optional[str] = None
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    organization: Optional[str] = None

class CompareItem(BaseModel):
    password: str
    security_score: int
    entropy_score: float
    risk_level: RiskLevel
    crack_time_formatted: str
    rank: int

class CompareResponse(BaseModel):
    comparisons: List[CompareItem]
