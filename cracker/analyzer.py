import re

COMMON_PATTERNS = [
    r'123', r'abc', r'password', r'admin', r'letmein',
    r'monkey', r'dragon', r'baseball', r'iloveyou', r'trustno1'
]


class PasswordAnalyzer:
    """Analyzes password strength and provides feedback."""

    def _score_length(self, length):
        """Return (score, feedback) for password length."""
        if length >= 12:
            return 25, '[+] Excellent length (12+ characters)'
        if length >= 8:
            return 15, '[+] Good length (8+ characters)'
        if length >= 6:
            return 5, '[~] Fair length (6+ characters)'
        return 0, '[-] Too short (less than 6 characters)'

    def _score_character_variety(self, password):
        """Return (score, feedback, char_flags) for character variety."""
        checks = [
            (r'[a-z]', 'lowercase letters'),
            (r'[A-Z]', 'uppercase letters'),
            (r'\d',    'digits'),
            (r'[^a-zA-Z0-9]', 'special characters'),
        ]
        score, feedback = 0, []
        flags = []
        for pattern, label in checks:
            found = bool(re.search(pattern, password))
            flags.append(found)
            if found:
                score += 15
                feedback.append(f'[+] Contains {label}')
            else:
                feedback.append(f'[-] No {label}')
        return score, feedback, flags

    def _score_patterns(self, password):
        """Return (penalty, feedback) for common and sequential patterns."""
        feedback = []
        penalty = 0
        for pattern in COMMON_PATTERNS:
            if re.search(pattern, password, re.IGNORECASE):
                penalty += 10
                feedback.append(f'[-] Contains common pattern: "{pattern}"')

        for i in range(len(password) - 2):
            if (ord(password[i + 1]) - ord(password[i]) == 1 and
                    ord(password[i + 2]) - ord(password[i + 1]) == 1):
                penalty += 5
                feedback.append('[-] Contains sequential characters')
                break
        return penalty, feedback

    def _build_suggestions(self, char_flags, length, pattern_penalty, seq_penalty):
        """Return improvement suggestions based on analysis flags."""
        has_lower, has_upper, has_digit, has_special = char_flags
        suggestions = []
        if not has_lower:
            suggestions.append('Add lowercase letters')
        if not has_upper:
            suggestions.append('Add uppercase letters')
        if not has_digit:
            suggestions.append('Add numbers')
        if not has_special:
            suggestions.append('Add special characters (!@#$%^&*)')
        if length < 12:
            suggestions.append('Make it longer (aim for 12+ characters)')
        if pattern_penalty > 0:
            suggestions.append('Avoid common words and patterns')
        if seq_penalty > 0:
            suggestions.append('Avoid sequential characters (abc, 123, etc.)')
        if not suggestions:
            suggestions.append('Your password is strong! Consider changing it periodically.')
        return suggestions

    def analyze_password(self, password):
        """
        Analyze password strength and provide feedback.

        Args:
            password (str): The password to analyze

        Returns:
            dict: Analysis results including strength score and suggestions
        """
        if not password:
            return {'strength': 'Empty', 'score': 0, 'feedback': ['Password is empty']}

        length = len(password)
        len_score, len_feedback = self._score_length(length)
        var_score, var_feedback, char_flags = self._score_character_variety(password)
        penalty, pat_feedback = self._score_patterns(password)

        seq_penalty = next(
            (5 for i in range(length - 2)
             if ord(password[i + 1]) - ord(password[i]) == 1
             and ord(password[i + 2]) - ord(password[i + 1]) == 1),
            0
        )
        pattern_penalty = penalty - (5 if seq_penalty else 0)

        score = max(0, len_score + var_score - penalty)
        feedback = [len_feedback] + var_feedback + pat_feedback

        if score >= 80:
            strength = 'Strong'
        elif score >= 60:
            strength = 'Medium'
        elif score >= 30:
            strength = 'Weak'
        else:
            strength = 'Very Weak'

        has_lower, has_upper, has_digit, has_special = char_flags
        return {
            'strength': strength,
            'score': score,
            'max_score': 100,
            'feedback': feedback,
            'suggestions': self._build_suggestions(char_flags, length, pattern_penalty, seq_penalty),
            'length': length,
            'character_analysis': {
                'lowercase': has_lower,
                'uppercase': has_upper,
                'digits': has_digit,
                'special': has_special
            }
        }
