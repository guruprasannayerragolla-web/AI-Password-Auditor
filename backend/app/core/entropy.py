import math
from collections import Counter
from typing import Dict, Any

def calculate_shannon_entropy(password: str) -> float:
    """
    Calculates the Shannon Entropy of a string.
    Formula: H = -sum(p_i * log2(p_i))
    Where p_i is the frequency probability of character i in the string.
    Shannon entropy measures the uncertainty/information content in the specific sequence.
    """
    if not password:
        return 0.0
        
    length = len(password)
    char_counts = Counter(password)
    
    entropy = 0.0
    for char, count in char_counts.items():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return round(entropy, 2)

def calculate_character_set_entropy(password: str, alphabet_size: int) -> float:
    """
    Calculates the traditional character set entropy (NIST style).
    Formula: E = L * log2(R)
    Where L is the password length, and R is the size of the character pool.
    """
    if not password or alphabet_size == 0:
        return 0.0
    length = len(password)
    return round(length * math.log2(alphabet_size), 2)

def calculate_effective_entropy(
    password: str, 
    char_set_entropy: float,
    pattern_count: int,
    dictionary_matched: bool,
    personal_info_exposure_count: int
) -> float:
    """
    Calculates the Effective Entropy.
    Subtracts entropy penalties from character set entropy based on human-generated patterns:
    - -5 bits per distinct non-random pattern.
    - -15 bits if containing a root dictionary word.
    - -20 bits if containing raw personal information.
    - -10% if uniqueness score is low.
    """
    if not password:
        return 0.0
        
    effective = char_set_entropy
    
    # Deductions
    effective -= pattern_count * 5.0
    if dictionary_matched:
        effective -= 15.0
    effective -= personal_info_exposure_count * 8.0
    
    # Repetition adjustment
    unique_ratio = len(set(password)) / len(password)
    if unique_ratio < 0.6:
        effective *= (unique_ratio + 0.4) # scale down entropy
        
    # Boundary guard
    effective = max(0.0, round(effective, 2))
    return effective

def get_entropy_category(entropy_value: float) -> str:
    """
    Categorizes the security strength of entropy bits.
    - < 28 bits: Very Weak (easily brute forced)
    - 28-35 bits: Weak
    - 36-59 bits: Medium
    - 60-79 bits: Strong
    - >= 80 bits: Very Strong (excellent resistance)
    """
    if entropy_value < 28:
        return "Very Low (Easily Guessable)"
    elif entropy_value < 36:
        return "Low (Vulnerable to Offline Attacks)"
    elif entropy_value < 60:
        return "Moderate (Acceptable for standard user accounts)"
    elif entropy_value < 80:
        return "High (Highly Secure)"
    else:
        return "Exceptional (Cryptographically Random / Passphrase)"

def analyze_entropy(
    password: str,
    alphabet_size: int,
    pattern_count: int = 0,
    dictionary_matched: bool = False,
    personal_info_count: int = 0
) -> Dict[str, Any]:
    """
    Performs complete entropy analysis and returns values, categories, and representations.
    """
    shannon = calculate_shannon_entropy(password)
    char_set_ent = calculate_character_set_entropy(password, alphabet_size)
    effective = calculate_effective_entropy(
        password, char_set_ent, pattern_count, dictionary_matched, personal_info_count
    )
    
    return {
        "shannon_entropy": shannon,
        "character_set_entropy": char_set_ent,
        "effective_entropy": effective,
        "category": get_entropy_category(effective),
        "randomness_index": round((shannon / 4.0) * 100, 1) if shannon <= 4.0 else 100.0
    }
