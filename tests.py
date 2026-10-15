"""
Basic tests for the password evaluation logic.
Run with:  python tests.py
All passwords below are made-up examples, not real credentials.
"""

import unittest

from app import (
    analyze_password, contains_common_word, has_digit, has_keyboard_pattern,
    has_lowercase, has_repeated_chars, has_sequence, has_special,
    has_uppercase, is_common_password, length_points, score_to_label,
)


class TestIndividualChecks(unittest.TestCase):
    def test_character_types(self):
        self.assertTrue(has_uppercase("abC"))
        self.assertFalse(has_uppercase("abc"))
        self.assertTrue(has_lowercase("ABc"))
        self.assertFalse(has_lowercase("ABC"))
        self.assertTrue(has_digit("a1"))
        self.assertFalse(has_digit("abc"))
        self.assertTrue(has_special("a!"))
        self.assertFalse(has_special("abc123"))

    def test_repeated_characters(self):
        self.assertTrue(has_repeated_chars("paaass"))
        self.assertTrue(has_repeated_chars("abab"))
        self.assertFalse(has_repeated_chars("abcdef"))

    def test_sequences(self):
        self.assertTrue(has_sequence("xabcx"))
        self.assertTrue(has_sequence("a321"))
        self.assertFalse(has_sequence("acegi"))
        self.assertFalse(has_sequence("a1b2"))

    def test_keyboard_patterns(self):
        self.assertTrue(has_keyboard_pattern("MyQwerty!"))
        self.assertTrue(has_keyboard_pattern("xpoiux"))  # reversed row
        self.assertFalse(has_keyboard_pattern("rhubarb"))

    def test_common_passwords(self):
        self.assertTrue(is_common_password("P@ssw0rd"))     # leetspeak version
        self.assertTrue(is_common_password("PASSWORD"))
        self.assertFalse(is_common_password("Zebra-Lantern-92"))
        self.assertTrue(contains_common_word("ilovefootball"))
        self.assertFalse(contains_common_word("Zebra-Lantern-92"))


class TestScoring(unittest.TestCase):
    def test_length_points(self):
        for length, expected in [(5, 0), (6, 5), (8, 15), (10, 25), (12, 40), (16, 50)]:
            self.assertEqual(length_points("x" * length), expected)

    def test_label_boundaries(self):
        cases = [(0, "Very Weak"), (24, "Very Weak"), (25, "Weak"), (44, "Weak"),
                 (45, "Moderate"), (64, "Moderate"), (65, "Strong"),
                 (84, "Strong"), (85, "Very Strong"), (100, "Very Strong")]
        for score, label in cases:
            self.assertEqual(score_to_label(score), label)

    def test_very_weak_examples(self):
        self.assertEqual(analyze_password("123456").label, "Very Weak")
        self.assertEqual(analyze_password("password").label, "Very Weak")
        self.assertEqual(analyze_password("a").label, "Very Weak")

    def test_weak_examples(self):
        # Contains a very common word, so it is capped at Weak
        self.assertEqual(analyze_password("Password123!").label, "Weak")
        self.assertEqual(analyze_password("sunshine1").label, "Weak")

    def test_moderate_example(self):
        # Mixed characters, but a predictable "Word + Year" shape
        self.assertEqual(analyze_password("Summer2024").label, "Moderate")

    def test_strong_example(self):
        self.assertEqual(analyze_password("Tr0ub4dor&3").label, "Strong")

    def test_very_strong_examples(self):
        self.assertEqual(analyze_password("correct horse battery staple").label, "Very Strong")
        self.assertEqual(analyze_password("vT7#kQ9!mLp2$xW4").label, "Very Strong")

    def test_longer_scores_higher(self):
        short = analyze_password("Tr0ub4dor&3").score
        longer = analyze_password("Tr0ub4dor&3-Lamp-Orbit").score
        self.assertGreater(longer, short)

    def test_score_is_in_range(self):
        for pw in ["", "a", "123456", "Tr0ub4dor&3", "x" * 128]:
            self.assertTrue(0 <= analyze_password(pw).score <= 100)


class TestSafetyAndErrors(unittest.TestCase):
    def test_empty_password(self):
        result = analyze_password("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.length, 0)

    def test_non_string_raises(self):
        with self.assertRaises(TypeError):
            analyze_password(None)

    def test_result_does_not_contain_password(self):
        pw = "Zq!8-notARealPassword"
        self.assertNotIn(pw, repr(analyze_password(pw)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
