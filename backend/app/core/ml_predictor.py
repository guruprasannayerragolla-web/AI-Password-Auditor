from typing import Dict, Any, Tuple
from ..config import settings

# Attempt to import numpy & scikit-learn packages.
# If they are missing, we fall back to a rule-based model to ensure the code remains executable.
HAS_ML_LIBS = False
np = None
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    import joblib
    HAS_ML_LIBS = True
except ImportError:
    pass

# Numerical categories matching RiskLevel enum:
# 0 = CRITICAL, 1 = HIGH, 2 = MEDIUM, 3 = LOW, 4 = SECURE
RISK_MAP = {
    0: "CRITICAL",
    1: "HIGH",
    2: "MEDIUM",
    3: "LOW",
    4: "SECURE"
}

def extract_features(
    password: str,
    composition: Dict[str, Any],
    entropy: float,
    pattern_count: int,
    dictionary_matched: bool,
    personal_info_exposure_count: int
):
    """
    Translates password audit data into a normalized feature vector for ML modeling.
    Features:
    0: Length
    1: Character set size (alphabet size)
    2: Shannon / Character set entropy
    3: Number of uppercase characters
    4: Number of digits
    5: Number of symbols
    6: Pattern count (keyboard walks, repeats, sequences)
    7: Dictionary match (0 or 1)
    8: Personal information match (0 or 1)
    9: Uniqueness score (unique characters / length)
    """
    length = len(password)
    has_dict = 1.0 if dictionary_matched else 0.0
    has_pi = 1.0 if personal_info_exposure_count > 0 else 0.0
    
    unique_ratio = len(set(password)) / length if length > 0 else 0.0
    
    features = [
        float(length),
        float(composition.get("alphabet_size", 0)),
        float(entropy),
        float(composition.get("upper_count", 0)),
        float(composition.get("digit_count", 0)),
        float(composition.get("symbol_count", 0)),
        float(pattern_count),
        float(has_dict),
        float(has_pi),
        float(unique_ratio)
    ]
    
    if np is not None:
        return np.array(features).reshape(1, -1)
    return [features]


def rule_based_fallback(
    password: str,
    entropy: float,
    pattern_count: int,
    dictionary_matched: bool,
    personal_info_exposure_count: int
) -> Tuple[str, float]:
    """
    A robust rule-based model simulating Random Forest classification.
    Used if sklearn is not installed.
    """
    length = len(password)
    
    if length < 6 or dictionary_matched and length < 10 or personal_info_exposure_count > 0 and length < 8:
        return "CRITICAL", 0.95
    elif length < 10 or dictionary_matched or pattern_count >= 2:
        return "HIGH", 0.88
    elif length < 14 and entropy < 50:
        return "MEDIUM", 0.82
    elif length >= 14 and entropy >= 70 and not dictionary_matched:
        return "SECURE", 0.94
    else:
        return "LOW", 0.90

def train_synthetic_model():
    """
    Generates synthetic data and trains a RandomForest model.
    Saves it to settings.MODEL_PATH.
    """
    if not HAS_ML_LIBS:
        print("[ML ENGINE] Scikit-Learn not found. Cannot train model.")
        return False
        
    print("[ML ENGINE] Training synthetic machine learning model...")
    # Create directory if missing
    os.makedirs(settings.MODEL_DIR, exist_ok=True)
    
    # Generate ~500 instances representing different security postures
    X = []
    y = []
    
    # Class 0: CRITICAL (short, dictionary matched, keyboard walks, name-based)
    for _ in range(100):
        # features: [length, alphabet_size, entropy, u_cnt, d_cnt, s_cnt, pat_cnt, dict_match, pi_match, unique_ratio]
        X.append([float(np.random.randint(1, 7)), 10.0, float(np.random.randint(1, 20)), 0.0, 3.0, 0.0, 1.0, 1.0, 0.0, 0.5])
        y.append(0)
        
    # Class 1: HIGH (moderate length, but has dictionary terms or sequential patterns)
    for _ in range(100):
        X.append([float(np.random.randint(8, 11)), 36.0, float(np.random.randint(20, 35)), 1.0, 2.0, 0.0, 2.0, 1.0, 0.0, 0.7])
        y.append(1)
        
    # Class 2: MEDIUM (length 10-12, mixed caps, some numbers, no dictionary but maybe some small pattern)
    for _ in range(100):
        X.append([float(np.random.randint(10, 13)), 62.0, float(np.random.randint(35, 55)), 2.0, 2.0, 1.0, 1.0, 0.0, 0.0, 0.8])
        y.append(2)
        
    # Class 3: LOW (length 12-15, mixed caps, numbers, symbols, low pattern, no dictionary matches)
    for _ in range(100):
        X.append([float(np.random.randint(12, 16)), 95.0, float(np.random.randint(55, 75)), 3.0, 3.0, 2.0, 0.0, 0.0, 0.0, 0.9])
        y.append(3)
        
    # Class 4: SECURE (length 16+, high entropy, completely random characters or long passphrase)
    for _ in range(100):
        X.append([float(np.random.randint(16, 25)), 95.0, float(np.random.randint(75, 120)), 4.0, 4.0, 3.0, 0.0, 0.0, 0.0, 0.95])
        y.append(4)
        
    X_arr = np.array(X)
    y_arr = np.array(y)
    
    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(X_arr, y_arr)
    
    joblib.dump(clf, settings.MODEL_PATH)
    print(f"[ML ENGINE] Model trained and saved to {settings.MODEL_PATH}")
    return True

# Initialize ML model
clf_model = None
if HAS_ML_LIBS:
    if not os.path.exists(settings.MODEL_PATH):
        try:
            train_synthetic_model()
        except Exception as e:
            print(f"[ML ENGINE] Training error during auto-initialize: {e}")
            
    if os.path.exists(settings.MODEL_PATH):
        try:
            clf_model = joblib.load(settings.MODEL_PATH)
            print("[ML ENGINE] Successfully loaded Random Forest model.")
        except Exception as e:
            print(f"[ML ENGINE] Failed to load ML model: {e}")

def predict_risk(
    password: str,
    composition: Dict[str, Any],
    entropy: float,
    pattern_count: int,
    dictionary_matched: bool,
    personal_info_exposure_count: int
) -> Tuple[str, float]:
    """
    Extracts features and evaluates password risk level using either
    the trained Random Forest classifier or the rule-based backup.
    Returns:
    - risk_level: str ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SECURE")
    - confidence: float (0.0 to 1.0 probability score)
    """
    if not HAS_ML_LIBS or clf_model is None:
        # Fall back to high-fidelity expert system
        return rule_based_fallback(
            password, entropy, pattern_count, dictionary_matched, personal_info_exposure_count
        )
        
    try:
        features = extract_features(
            password, composition, entropy, pattern_count, dictionary_matched, personal_info_exposure_count
        )
        prediction = clf_model.predict(features)[0]
        probabilities = clf_model.predict_proba(features)[0]
        confidence = float(probabilities[prediction])
        
        return RISK_MAP.get(prediction, "MEDIUM"), confidence
    except Exception as e:
        print(f"[ML ENGINE] Prediction error: {e}. Running fallback.")
        return rule_based_fallback(
            password, entropy, pattern_count, dictionary_matched, personal_info_exposure_count
        )
