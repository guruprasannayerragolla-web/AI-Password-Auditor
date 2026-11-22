from typing import List, Dict, Any

def generate_recommendations(
    password: str,
    security_score: int,
    entropy: float,
    patterns: List[Dict[str, Any]],
    dictionary_matched: bool,
    personal_info_exposures: List[Dict[str, Any]],
    composition: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Analyzes metrics and yields prioritized remediation cards for the security dashboard.
    Each item has code, text description, and priority level.
    """
    recs = []
    length = len(password)
    
    if length == 0:
        return recs
        
    # 1. Critical Priority: Length & Dictionary
    if length < 8:
        recs.append({
            "recommendation_code": "CRIT_LENGTH",
            "recommendation_text": "Critical: Increase length immediately. Your password is under 8 characters. Passwords should be at least 12-16 characters.",
            "priority": "HIGH"
        })
    elif length < 12:
        recs.append({
            "recommendation_code": "WARN_LENGTH",
            "recommendation_text": "Increase length. Lengthening your password is the single most effective way to exponentially increase cracking time.",
            "priority": "MEDIUM"
        })
        
    if dictionary_matched:
        recs.append({
            "recommendation_code": "BAN_DICTIONARY",
            "recommendation_text": "Avoid dictionary words. Hacking tools use pre-computed dictionaries and will crack words instantly, even if you add numbers at the end.",
            "priority": "HIGH"
        })
        
    if personal_info_exposures:
        recs.append({
            "recommendation_code": "BAN_PERSONAL",
            "recommendation_text": "Remove personal details. Do not embed usernames, emails, names, or your organization's name. This info is easily harvestable via OSINT.",
            "priority": "HIGH"
        })
        
    # 2. Pattern Remediation
    if patterns:
        walks = any(p["pattern_type"] == "KEYBOARD_WALK" for p in patterns)
        seqs = any(p["pattern_type"] == "SEQUENCE" for p in patterns)
        repeats = any(p["pattern_type"] == "REPEATED_CHAR" for p in patterns)
        
        if walks:
            recs.append({
                "recommendation_code": "REMOVE_WALKS",
                "recommendation_text": "Avoid keyboard patterns. Do not use geometric runs like 'qwerty', 'asdf', or diagonal lines. Cracking rules test these automatically.",
                "priority": "HIGH"
            })
        if seqs:
            recs.append({
                "recommendation_code": "REMOVE_SEQUENCES",
                "recommendation_text": "Remove character runs. Sequences like '12345' or 'abc' are easily guessed by dictionary-hybrid rules.",
                "priority": "MEDIUM"
            })
        if repeats:
            recs.append({
                "recommendation_code": "REMOVE_REPETITIONS",
                "recommendation_text": "Reduce character repetition. Repeated letters like 'aaaa' or '111' do not add mathematical entropy and waste character budget.",
                "priority": "MEDIUM"
            })
            
    # 3. Diversity Remediations
    if not composition.get("has_symbols", False):
        recs.append({
            "recommendation_code": "ADD_SYMBOLS",
            "recommendation_text": "Include special characters. Adding symbols (e.g. $, !, @, #, _) expands the search alphabet from 62 to 95+ characters, slowing down brute-force tools.",
            "priority": "MEDIUM"
        })
    if not composition.get("has_upper", False) or not composition.get("has_lower", False):
        recs.append({
            "recommendation_code": "ADD_CASE",
            "recommendation_text": "Mix casing. Use a combination of uppercase and lowercase letters to force crackers to search larger character sets.",
            "priority": "LOW"
        })
        
    # 4. Constructive Suggestion
    if security_score < 80:
        recs.append({
            "recommendation_code": "USE_PASSPHRASE",
            "recommendation_text": "Switch to a Passphrase. Combine 4 random, unrelated words (e.g., 'correct-horse-battery-staple'). This achieves exceptionally high entropy while being easy to memorize.",
            "priority": "MEDIUM"
        })
        
    return recs
