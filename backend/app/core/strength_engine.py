import string
from collections import Counter
from typing import Dict, Any

def analyze_character_composition(password: str) -> Dict[str, Any]:
    """
    Analyzes the presence of character sets: uppercase, lowercase, digits, symbols.
    """
    length = len(password)
    if length == 0:
        return {
            "length": 0, "has_upper": False, "has_lower": False, "has_digits": False, "has_symbols": False,
            "upper_count": 0, "lower_count": 0, "digit_count": 0, "symbol_count": 0, "alphabet_size": 0
        }
        
    upper = sum(1 for c in password if c.isupper())
    lower = sum(1 for c in password if c.islower())
    digits = sum(1 for c in password if c.isdigit())
    symbols = sum(1 for c in password if c in string.punctuation or (not c.isalnum() and not c.isspace()))
    
    # Calculate the size of the alphabet pool
    alphabet_size = 0
    if upper > 0: alphabet_size += 26
    if lower > 0: alphabet_size += 26
    if digits > 0: alphabet_size += 10
    if symbols > 0: alphabet_size += 33 # standard punctuation size in python
    if any(c.isspace() for c in password): alphabet_size += 1
    
    return {
        "length": length,
        "has_upper": upper > 0,
        "has_lower": lower > 0,
        "has_digits": digits > 0,
        "has_symbols": symbols > 0,
        "upper_count": upper,
        "lower_count": lower,
        "digit_count": digits,
        "symbol_count": symbols,
        "alphabet_size": alphabet_size
    }

def calculate_symbol_distribution_score(password: str) -> float:
    """
    Checks where symbols are placed. If symbols are only at the beginning or end,
    it represents a human-predictable design and scores lower.
    If symbols are placed in the middle (e.g., p@ssword vs password!), it scores higher.
    """
    length = len(password)
    if length <= 2:
        return 0.0
        
    symbols_indices = [i for i, c in enumerate(password) if c in string.punctuation or (not c.isalnum() and not c.isspace())]
    if not symbols_indices:
        return 0.0
        
    # Check what fraction of symbols are in the middle of the password (excluding first and last index)
    mid_symbols = sum(1 for idx in symbols_indices if 0 < idx < length - 1)
    return float(mid_symbols) / len(symbols_indices)

def calculate_uniqueness_score(password: str) -> float:
    """
    Measures character diversity relative to length.
    A password like 'aaaaaa' has a uniqueness score of 1/6 = 0.16.
    'abcdef' has 6/6 = 1.0.
    """
    if not password:
        return 0.0
    unique_chars = len(set(password))
    return float(unique_chars) / len(password)

def calculate_strength_and_complexity(password: str) -> Dict[str, Any]:
    """
    Integrates character metrics, diversity, and length to return:
    - complexity_score: 0-100 base score
    - security_score: final heuristic strength (0-100)
    - classification: text evaluation
    """
    composition = analyze_character_composition(password)
    length = composition["length"]
    
    if length == 0:
        return {
            "security_score": 0,
            "confidence_score": 1.0,
            "classification": "Insecure",
            "complexity_score": 0,
            "uniqueness_score": 0.0,
            "composition": composition,
            "symbol_distribution": 0.0
        }
        
    # Base score calculated using length and character pools
    # Standard rule of thumb: length carries high weight, character sets add multipliers
    length_pts = min(length * 4, 40) # Max 40 points for length up to 10
    if length > 10:
        length_pts += min((length - 10) * 3, 20) # Max 60 points total for length up to 17+
        
    # Pool size bonus
    pool_bonus = min(composition["alphabet_size"] / 95 * 20, 20) # Max 20 points
    
    # Variety bonus (number of distinct character classes used)
    classes_used = sum([
        composition["has_upper"],
        composition["has_lower"],
        composition["has_digits"],
        composition["has_symbols"]
    ])
    variety_bonus = classes_used * 5 # Max 20 points
    
    # Deductions
    uniqueness = calculate_uniqueness_score(password)
    uniqueness_penalty = 0.0
    if uniqueness < 0.5:
        # High repetition, deduct up to 15 points
        uniqueness_penalty = (0.5 - uniqueness) * 30
        
    # Symbol placement
    symbol_dist = calculate_symbol_distribution_score(password)
    symbol_placement_bonus = 0.0
    if composition["has_symbols"] and symbol_dist > 0:
        symbol_placement_bonus = symbol_dist * 5.0 # Max 5 points
        
    complexity = max(0.0, min(100.0, length_pts + pool_bonus + variety_bonus + symbol_placement_bonus - uniqueness_penalty))
    
    # Classification & confidence mapping
    if complexity < 30:
        classification = "Very Weak"
        confidence = 0.95
    elif complexity < 50:
        classification = "Weak"
        confidence = 0.90
    elif complexity < 70:
        classification = "Moderate"
        confidence = 0.85
    elif complexity < 85:
        classification = "Strong"
        confidence = 0.90
    else:
        classification = "Excellent"
        confidence = 0.95
        
    return {
        "security_score": int(complexity),
        "confidence_score": confidence,
        "classification": classification,
        "complexity_score": int(complexity),
        "uniqueness_score": round(uniqueness, 3),
        "composition": composition,
        "symbol_distribution": round(symbol_dist, 3)
    }
