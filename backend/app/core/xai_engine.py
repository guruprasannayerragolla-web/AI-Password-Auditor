from typing import List, Dict, Any

def generate_xai_explanation(
    password: str,
    security_score: int,
    entropy: float,
    patterns: List[Dict[str, Any]],
    dictionary_matched: bool,
    matched_dictionary_term: str,
    personal_info_exposures: List[Dict[str, Any]],
    risk_level: str
) -> str:
    """
    Generates a natural, human-readable Explainable AI (XAI) assessment of the password.
    Explains the combination of factors leading to the model's final risk prediction.
    """
    length = len(password)
    
    if length == 0:
        return "No password was provided. Please enter a password to run the analysis."
        
    explanations = []
    
    # 1. Base Evaluation
    if risk_level == "SECURE":
        return (
            f"The ML model predicts a 'SECURE' status with high confidence. The password features an excellent length "
            f"({length} characters) and robust Effective Entropy ({entropy} bits). It is structured without any common "
            f"dictionary words, keyboard walk patterns, or personal references, rendering it highly resilient to GPU "
            f"hashing clusters and AI-assisted brute force."
        )
        
    # 2. Critical/High Risk cases (Dictionary/Personal Info/Extreme patterns)
    if dictionary_matched:
        match_type = "a direct" if matched_dictionary_term == password else "an embedded"
        explanations.append(
            f"contains {match_type} dictionary term or common word/sequence ('{matched_dictionary_term}'). "
            f"This makes it highly vulnerable to hybrid dictionary attacks where hacking tools quickly append numbers "
            f"and symbols to common terms."
        )
        
    if personal_info_exposures:
        exposed_fields = [exp["field_exposed"] for exp in personal_info_exposures]
        fields_str = ", ".join(set(exposed_fields))
        explanations.append(
            f"directly exposes personal data matching your {fields_str}. Attackers utilize Open Source Intelligence "
            f"(OSINT) from social media and email profiles to target usernames first, bypassing complex characters."
        )
        
    if patterns:
        walks = [p["pattern_value"] for p in patterns if p["pattern_type"] == "KEYBOARD_WALK"]
        seqs = [p["pattern_value"] for p in patterns if p["pattern_type"] == "SEQUENCE"]
        repeats = [p["pattern_value"] for p in patterns if p["pattern_type"] == "REPEATED_CHAR"]
        
        pattern_details = []
        if walks:
            pattern_details.append(f"keyboard walks ('{', '.join(walks)}')")
        if seqs:
            pattern_details.append(f"consecutive sequences ('{', '.join(seqs)}')")
        if repeats:
            pattern_details.append(f"repeated characters ('{', '.join(repeats)}')")
            
        explanations.append(
            f"incorporates predictable human patterns: {', '.join(pattern_details)}. "
            f"Standard password cracking utilities like Hashcat apply rule engines that prioritize these patterns."
        )
        
    # 3. Structural cases (Length and Entropy)
    if length < 8:
        explanations.append(
            f"is critically short ({length} characters). Regardless of character diversity (symbols/digits), "
            f"short length limits the total mathematical combinations, allowing modern offline GPU cracking arrays "
            f"to brute-force the password in seconds."
        )
    elif length < 12 and entropy < 50:
        explanations.append(
            f"is moderately short ({length} characters) with low Effective Entropy ({entropy} bits). "
            f"While it might resist simple guessing, it remains highly vulnerable to offline dictionary-hybrid attacks."
        )
        
    # 4. Formulate the response
    if not explanations:
        # Moderate strength, safe but could be better
        return (
            f"The password has moderate strength (Score: {security_score}/100, Entropy: {entropy} bits). "
            f"It does not contain direct dictionary matches or personal identifiers, but its length of {length} "
            f"characters is not long enough to survive advanced offline brute-force attacks if the database is leaked."
        )
        
    # Compile explanations into a beautiful cybersecurity brief
    summary = f"The ML model predicts a '{risk_level}' status. The password "
    if len(explanations) == 1:
        summary += explanations[0]
    else:
        summary += "; it ".join(explanations[:-1]) + "; and it " + explanations[-1]
        
    return summary
