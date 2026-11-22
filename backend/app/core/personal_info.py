import re
from typing import List, Dict, Any
from .patterns import decode_leetspeak

def analyze_personal_info_exposure(
    password: str,
    username: str = None,
    email: str = None,
    first_name: str = None,
    last_name: str = None,
    organization: str = None
) -> List[Dict[str, Any]]:
    """
    Checks if personal information is contained within the password.
    Identifies exact, substring, reverse, and leetspeak mutations of personal fields.
    """
    exposures = []
    pwd_lower = password.lower()
    pwd_leet = decode_leetspeak(password).lower()
    
    fields = {
        "USERNAME": username,
        "EMAIL": email,
        "FIRST_NAME": first_name,
        "LAST_NAME": last_name,
        "ORGANIZATION": organization
    }
    
    # Filter out empty fields and ensure strings are clean
    active_fields = {k: str(v).strip().lower() for k, v in fields.items() if v and len(str(v).strip()) >= 3}
    
    # Process email specially (take username part)
    if "EMAIL" in active_fields:
        email_val = active_fields["EMAIL"]
        if "@" in email_val:
            email_part = email_val.split("@")[0]
            if len(email_part) >= 3:
                active_fields["EMAIL_PREFIX"] = email_part
    
    for field_name, value in active_fields.items():
        # 1. Exact Match
        if pwd_lower == value:
            exposures.append({
                "field_exposed": field_name,
                "matched_substring": password,
                "match_type": "EXACT"
            })
            continue
            
        # 2. Substring Match
        idx = pwd_lower.find(value)
        if idx != -1:
            exposures.append({
                "field_exposed": field_name,
                "matched_substring": password[idx:idx+len(value)],
                "match_type": "SUBSTRING"
            })
            continue
            
        # 3. Leet-mutation Match
        idx_leet = pwd_leet.find(value)
        if idx_leet != -1:
            exposures.append({
                "field_exposed": field_name,
                "matched_substring": password[idx_leet:idx_leet+len(value)],
                "match_type": "LEET_MUTATION"
            })
            continue
            
        # 4. Reverse Match
        reversed_val = value[::-1]
        idx_rev = pwd_lower.find(reversed_val)
        if idx_rev != -1:
            exposures.append({
                "field_exposed": field_name,
                "matched_substring": password[idx_rev:idx_rev+len(reversed_val)],
                "match_type": "REVERSE_SUBSTRING"
            })
            
    return exposures
