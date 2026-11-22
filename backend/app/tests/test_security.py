import pytest
from ..core.entropy import calculate_shannon_entropy, calculate_character_set_entropy
from ..core.patterns import detect_patterns
from ..core.dictionary import check_dictionary_vulnerability
from ..core.personal_info import analyze_personal_info_exposure

def test_shannon_entropy():
    # Repetitive characters should have zero entropy
    assert calculate_shannon_entropy("aaaaa") == 0.0
    # Fully unique character strings should have logarithmic value
    assert calculate_shannon_entropy("abcd") == 2.0
    # Empty string should yield 0.0
    assert calculate_shannon_entropy("") == 0.0

def test_character_set_entropy():
    # Length 4, alphabet size 10 (digits only) -> 4 * log2(10) = 4 * 3.3219 = 13.29
    assert calculate_character_set_entropy("1234", 10) == 13.29
    # Empty string
    assert calculate_character_set_entropy("", 95) == 0.0

def test_pattern_detector():
    # Repeated chars
    repeats = detect_patterns("aaaaa")
    assert len(repeats) == 1
    assert repeats[0]["pattern_type"] == "REPEATED_CHAR"
    assert repeats[0]["pattern_value"] == "aaaaa"

    # Numeric sequence
    seqs = detect_patterns("12345")
    assert len(seqs) == 1
    assert seqs[0]["pattern_type"] == "SEQUENCE"
    assert seqs[0]["pattern_value"] == "12345"

    # Keyboard walk
    walks = detect_patterns("qwerty")
    assert len(walks) == 1
    assert walks[0]["pattern_type"] == "KEYBOARD_WALK"
    assert walks[0]["pattern_value"] == "qwerty"

def test_dictionary_vulnerability():
    # Exact word match
    matched, score, term = check_dictionary_vulnerability("password")
    assert matched is True
    assert score == 1.0
    assert term == "password"

    # Leetspeak mutation match
    matched, score, term = check_dictionary_vulnerability("p@$$w0rd")
    assert matched is True
    assert score > 0.70
    assert term == "password"

    # Not in dictionary
    matched, score, term = check_dictionary_vulnerability("XyZ9!fG_2b")
    assert matched is False

def test_personal_info_exposure():
    # Username leak
    exposures = analyze_personal_info_exposure("john123!", username="john")
    assert len(exposures) == 1
    assert exposures[0]["field_exposed"] == "USERNAME"
    assert exposures[0]["match_type"] == "SUBSTRING"

    # Leet name leak
    exposures = analyze_personal_info_exposure("J0hndoe!", first_name="john")
    assert len(exposures) == 1
    assert exposures[0]["field_exposed"] == "FIRST_NAME"
    assert exposures[0]["match_type"] == "LEET_MUTATION"
