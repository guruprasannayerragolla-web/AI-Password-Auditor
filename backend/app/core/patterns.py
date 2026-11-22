import re
from typing import List, Dict, Any

# Keyboard layout row/diagonal sequences for walking detection
KEYBOARD_WALKS = [
    # Horizontal forward/backward
    "1234567890-=", "=-0987654321",
    "qwertyuiop", "poiuytrewq",
    "asdfghjkl", "lkjhgfdsa",
    "zxcvbnm", "mnbvcxz",
    # Diagonal paths
    "qaz", "zaq", "wsx", "xsw", "edc", "cde", "rfv", "vfr", "tgb", "bgt", 
    "yhn", "nhy", "ujm", "mju", "ik,", ",ki", "ol.", ".lo", "p;/", "/;p"
]

LEET_MAP = {
    '@': 'a', '4': 'a',
    '3': 'e',
    '1': 'i', '!': 'i', '|': 'i',
    '0': 'o',
    '5': 's', '$': 's',
    '7': 't', '+': 't',
    '8': 'b',
    '9': 'g',
    '2': 'z'
}

def decode_leetspeak(password: str) -> str:
    """
    Translates basic leetspeak symbols back to their alphabet equivalents.
    E.g., "p@$$w0rd" -> "password"
    """
    decoded = []
    for char in password.lower():
        decoded.append(LEET_MAP.get(char, char))
    return "".join(decoded)

def find_repeats(password: str) -> List[Dict[str, Any]]:
    """
    Detects adjacent repeated characters. E.g. 'aaaa' (length >= 3)
    """
    patterns = []
    length = len(password)
    if length < 3:
        return patterns
        
    i = 0
    while i < length:
        j = i + 1
        while j < length and password[j] == password[i]:
            j += 1
        run_len = j - i
        if run_len >= 3:
            patterns.append({
                "pattern_type": "REPEATED_CHAR",
                "pattern_value": password[i:j],
                "start_index": i,
                "end_index": j - 1,
                "severity": "HIGH" if run_len > 4 else "MEDIUM"
            })
            i = j
        else:
            i += 1
    return patterns

def find_sequences(password: str) -> List[Dict[str, Any]]:
    """
    Detects alphabetical or numerical sequences. E.g. 'abcde', '98765' (length >= 3)
    """
    patterns = []
    length = len(password)
    if length < 3:
        return patterns
        
    # Check ASCII values for sequential steps
    i = 0
    while i < length:
        # Ascending
        j_asc = i + 1
        while j_asc < length and ord(password[j_asc].lower()) - ord(password[j_asc - 1].lower()) == 1:
            # Prevent counting symbols/spaces as alphabetic sequences
            if not password[j_asc].isalnum() or not password[j_asc-1].isalnum():
                break
            j_asc += 1
            
        # Descending
        j_desc = i + 1
        while j_desc < length and ord(password[j_desc].lower()) - ord(password[j_desc - 1].lower()) == -1:
            if not password[j_desc].isalnum() or not password[j_desc-1].isalnum():
                break
            j_desc += 1
            
        asc_len = j_asc - i
        desc_len = j_desc - i
        
        if asc_len >= 3:
            patterns.append({
                "pattern_type": "SEQUENCE",
                "pattern_value": password[i:j_asc],
                "start_index": i,
                "end_index": j_asc - 1,
                "severity": "HIGH" if asc_len > 4 else "MEDIUM"
            })
            i = j_asc
        elif desc_len >= 3:
            patterns.append({
                "pattern_type": "SEQUENCE",
                "pattern_value": password[i:j_desc],
                "start_index": i,
                "end_index": j_desc - 1,
                "severity": "HIGH" if desc_len > 4 else "MEDIUM"
            })
            i = j_desc
        else:
            i += 1
            
    return patterns

def find_keyboard_walks(password: str) -> List[Dict[str, Any]]:
    """
    Looks for sequences that match keyboard patterns (qwerty, asdf, etc.)
    """
    patterns = []
    pwd_lower = password.lower()
    length = len(pwd_lower)
    
    # We check substrings of length 3 to 8
    for walk in KEYBOARD_WALKS:
        walk_len = len(walk)
        for w_sub_len in range(8, 2, -1): # Check larger patterns first
            for start in range(walk_len - w_sub_len + 1):
                sub = walk[start:start + w_sub_len]
                idx = pwd_lower.find(sub)
                if idx != -1:
                    # Verify we haven't already covered this sequence with a bigger keyboard walk
                    overlap = False
                    for existing in patterns:
                        if existing["start_index"] <= idx and existing["end_index"] >= (idx + w_sub_len - 1):
                            overlap = True
                            break
                    if not overlap:
                        patterns.append({
                            "pattern_type": "KEYBOARD_WALK",
                            "pattern_value": password[idx:idx + w_sub_len],
                            "start_index": idx,
                            "end_index": idx + w_sub_len - 1,
                            "severity": "HIGH" if w_sub_len >= 5 else "MEDIUM"
                        })
    return patterns

def find_date_patterns(password: str) -> List[Dict[str, Any]]:
    """
    Detects 4-digit years (e.g. 1980, 2024, 2005) or dates in password (DDMMYY / MMDDYY).
    """
    patterns = []
    # Match years 1900-2029
    for match in re.finditer(r"\b(19\d\d|20[0-2]\d)\b", password):
        patterns.append({
            "pattern_type": "DATE_PATTERN",
            "pattern_value": match.group(),
            "start_index": match.start(),
            "end_index": match.end() - 1,
            "severity": "HIGH"
        })
    return patterns

def detect_patterns(password: str) -> List[Dict[str, Any]]:
    """
    Runs all pattern detection techniques and consolidates non-overlapping results.
    """
    all_patterns = []
    
    # Run tests
    all_patterns.extend(find_repeats(password))
    all_patterns.extend(find_sequences(password))
    all_patterns.extend(find_keyboard_walks(password))
    all_patterns.extend(find_date_patterns(password))
    
    # Sort by start_index, then end_index descending
    all_patterns.sort(key=lambda x: (x["start_index"], -x["end_index"]))
    
    # Filter out nested patterns (deduplication)
    filtered_patterns = []
    last_end = -1
    for p in all_patterns:
        if p["start_index"] > last_end:
            filtered_patterns.append(p)
            last_end = p["end_index"]
            
    return filtered_patterns
