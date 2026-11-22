from typing import Dict, Any, Tuple
import math

def format_time(seconds: float) -> str:
    """
    Converts a raw count of seconds into a human-readable duration string.
    """
    if seconds < 1e-3:
        return "Instantaneous (< 1 millisecond)"
    elif seconds < 1:
        return f"{round(seconds * 1000, 1)} milliseconds"
    elif seconds < 60:
        return f"{round(seconds, 1)} seconds"
    elif seconds < 3600:
        return f"{int(seconds // 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds // 3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds // 86400)} days"
    elif seconds < 31536000 * 100:
        return f"{int(seconds // 31536000)} years"
    elif seconds < 31536000 * 1000000:
        return f"{int(seconds // (31536000 * 1000))} millennia"
    else:
        return "Centuries (Cryptographically Secure)"

def estimate_crack_resistance(
    password: str,
    alphabet_size: int,
    entropy: float,
    pattern_count: int,
    dictionary_matched: bool
) -> Dict[str, Any]:
    """
    Calculates cracking time under different hardware and methodology conditions.
    """
    length = len(password)
    if length == 0:
        return {
            "online_throttled_seconds": 0.0,
            "offline_fast_hash_seconds": 0.0,
            "offline_slow_hash_seconds": 0.0,
            "ai_assisted_seconds": 0.0,
            "realistic_crack_time_seconds": 0.0,
            "realistic_crack_time_formatted": "Instantaneous",
            "difficulty_score": 0
        }
        
    # Total combinations search space
    search_space = float(alphabet_size) ** length
    
    # 1. Online Throttled Attack (e.g. login portal, 10 attempts per second)
    online_speed = 10.0 # attempts/sec
    online_seconds = (search_space / 2) / online_speed
    
    # 2. Offline Fast Hashing (e.g. MD5/SHA-256 using specialized GPU cluster - 100 Billion hashes/sec)
    # RTX 4090 hash rate for MD5 is approx 120 GH/s, let's use 1.0e11
    gpu_fast_speed = 1.0e11
    offline_fast_seconds = (search_space / 2) / gpu_fast_speed
    
    # If password is in the dictionary, offline cracking is immediate
    if dictionary_matched:
        offline_fast_seconds = min(offline_fast_seconds, 0.005)
        
    # 3. Offline Slow Hashing (e.g. Bcrypt/Argon2 - 10,000 hashes/sec due to salting and key stretching)
    gpu_slow_speed = 10000.0
    offline_slow_seconds = (search_space / 2) / gpu_slow_speed
    if dictionary_matched:
        offline_slow_seconds = min(offline_slow_seconds, 0.5)
        
    # 4. AI-Assisted Password Guessing (PassGAN / Rule-based Guessing)
    # Humans make predictable passwords. Neural networks guess these structures first.
    # We simulate this by reducing search space exponentially based on patterns
    ai_search_reduction = 1.0
    if pattern_count > 0:
        ai_search_reduction *= (10 ** (pattern_count * 1.5))
    if dictionary_matched:
        ai_search_reduction *= 1.0e5
        
    ai_effective_space = max(2.0, search_space / ai_search_reduction)
    ai_speed = 1.0e7 # Simulating high speed model checking 10 Million candidate generation/sec
    ai_seconds = (ai_effective_space / 2) / ai_speed
    if dictionary_matched:
        ai_seconds = min(ai_seconds, 0.01)
        
    # Realistic crack time is the easiest route an attacker would choose (Offline Fast / AI Guessing)
    realistic_seconds = min(offline_fast_seconds, ai_seconds)
    if dictionary_matched:
        realistic_seconds = min(realistic_seconds, 0.001)
        
    # Calculate Difficulty Score (0-100)
    # Map realistic crack time logarithmically. 100 points = ~100 years offline crack time
    # log10(100 years in seconds) = log10(3.15e9) = 9.5. Let's scale relative to that.
    if realistic_seconds <= 1.0:
        difficulty = min(15, int(length * 1.5))
    else:
        difficulty = int(min(100.0, 15 + (math.log10(realistic_seconds) / 9.5) * 85.0))
        
    # Apply pattern penalty to difficulty
    difficulty = max(0, difficulty - (pattern_count * 8))
    if dictionary_matched:
        difficulty = max(0, min(10, difficulty))
        
    return {
        "online_throttled_seconds": online_seconds,
        "offline_fast_hash_seconds": offline_fast_seconds,
        "offline_slow_hash_seconds": offline_slow_seconds,
        "ai_assisted_seconds": ai_seconds,
        "realistic_crack_time_seconds": realistic_seconds,
        "realistic_crack_time_formatted": format_time(realistic_seconds),
        "difficulty_score": int(difficulty)
    }
