"""
Attack Modules

This package contains various password cracking attack implementations:
- DictionaryAttack: Wordlist-based cracking
- BruteForceAttack: Systematic character combination generation
- HybridAttack: Combination of dictionary and pattern-based attacks
- RuleBasedAttack: Transformation-based cracking
"""

from .dictionary import DictionaryAttack
from .brute_force import BruteForceAttack
from .hybrid import HybridAttack
from .rule_based import RuleBasedAttack

__all__ = ['DictionaryAttack', 'BruteForceAttack', 'HybridAttack', 'RuleBasedAttack']