from typing import Tuple, Set
from .patterns import decode_leetspeak

# A list of highly common passwords, system defaults, and dictionary terms
# representing the core patterns found in databases like RockYou.
COMMON_DICTS: Set[str] = {
    "password", "123456", "123456789", "12345", "1234567", "12345678", "1234", "111111",
    "qwerty", "asdfgh", "drowssap", "letmein", "welcome", "admin", "administrator",
    "guest", "secret", "login", "password123", "pass123", "changeit", "password1",
    "oracle", "root", "system", "backup", "testing", "security", "auditor", "system123",
    "shadow", "master", "football", "baseball", "soccer", "monkey", "dragon", "kitty",
    "mustang", "killer", "rookie", "superman", "batman", "trustnoone", "loveme", "iloveyou",
    "princess", "sunshine", "charlie", "michael", "jessica", "william", "alexander",
    "elizabeth", "spiderman", "matrix", "infinity", "universe", "freedom", "america",
    "london", "tokyo", "berlin", "summer", "winter", "spring", "autumn", "january",
    "december", "monday", "sunday", "server", "database", "network", "firewall", "router"
}

def clean_password_for_dictionary(password: str) -> str:
    """
    Cleans a password for matching against dictionary.
    Strips trailing and leading numbers/special characters.
    E.g. "!!admin123" -> "admin"
    """
    cleaned = password.lower().strip()
    # Strip leading/trailing punctuation and numbers
    cleaned = cleaned.strip("0123456789!@#$%^&*()-_=+[]{}|;:',.<>/?`~")
    return cleaned

def check_dictionary_vulnerability(password: str) -> Tuple[bool, float, str]:
    """
    Checks if the password is vulnerable to dictionary attack.
    Returns:
    - matched: bool (whether a dictionary match was found)
    - vulnerability_score: float (0.0 to 1.0, where 1.0 is extremely vulnerable)
    - matched_term: str (the term matched, if any)
    """
    pwd_lower = password.lower()
    
    # 1. Direct match on raw input
    if pwd_lower in COMMON_DICTS:
        return True, 1.0, password
        
    # 2. Leetspeak decoded match
    pwd_leet = decode_leetspeak(password)
    if pwd_leet in COMMON_DICTS:
        return True, 0.95, pwd_leet
        
    # 3. Cleaned word match (stripping numbers/punctuation)
    pwd_clean = clean_password_for_dictionary(password)
    if len(pwd_clean) >= 3 and pwd_clean in COMMON_DICTS:
        return True, 0.85, pwd_clean
        
    # 4. Leetspeak + Cleaned word match
    pwd_leet_clean = clean_password_for_dictionary(pwd_leet)
    if len(pwd_leet_clean) >= 3 and pwd_leet_clean in COMMON_DICTS:
        return True, 0.80, pwd_leet_clean
        
    # 5. Check if any word from the dictionary is embedded in the password (length >= 4)
    for term in COMMON_DICTS:
        if len(term) >= 4 and term in pwd_lower:
            return True, 0.70, term
            
    # No matches found
    return False, 0.0, ""
