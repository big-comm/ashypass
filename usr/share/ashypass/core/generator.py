#!/usr/bin/env python3
"""
Ashy Pass - Password Generator Module
Cryptographically secure password generation
"""

import secrets
import string
from dataclasses import dataclass
from typing import Tuple

from core.config import AMBIGUOUS_CHARS, DEFAULT_SYMBOLS, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH
from utils.i18n import _


@dataclass
class PasswordConfig:
    """Configuration for password generation"""
    length: int = 16
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = True
    custom_symbols: str = ""


class PasswordGenerator:
    """Cryptographically secure password generator"""
    
    # Common words for passphrase generation
    PASSPHRASE_WORDS = [
        "able", "about", "above", "accept", "action", "active", "actual", "advance", "advice",
        "afraid", "after", "again", "against", "agency", "agent", "agree", "ahead", "allow",
        "almost", "alone", "along", "already", "always", "amount", "ancient", "angle", "angry",
        "animal", "annual", "another", "answer", "anyone", "apart", "appear", "apple", "apply",
        "approve", "april", "area", "argue", "arise", "around", "arrive", "artist", "aside",
        "assault", "asset", "assist", "assume", "attack", "attempt", "attend", "attract", "author",
        "autumn", "avenue", "avoid", "awake", "award", "aware", "balance", "barrel", "barrier",
        "battle", "beach", "beauty", "become", "before", "begin", "behalf", "behave", "behind",
        "belief", "belong", "below", "benefit", "beside", "better", "between", "beyond", "blame",
        "branch", "brave", "bread", "break", "bridge", "brief", "bright", "bring", "broken",
        "brother", "brown", "budget", "build", "burden", "button", "camera", "cancel", "cancer",
        "cannot", "canvas", "capable", "capital", "carbon", "career", "careful", "carpet", "carry",
        "castle", "casual", "catch", "cause", "ceiling", "center", "central", "century", "certain",
        "chair", "challenge", "chance", "change", "channel", "chapter", "charge", "chart", "chase",
        "cheap", "check", "chemical", "chest", "chicken", "chief", "child", "choice", "choose",
        "church", "circle", "citizen", "civil", "claim", "class", "classic", "clean", "clear",
        "client", "climate", "climb", "clock", "close", "cloud", "coach", "coast",
    ]
    
    def generate_password(self, config: PasswordConfig) -> str:
        """Generate a cryptographically secure password"""
        if config.length < MIN_PASSWORD_LENGTH or config.length > MAX_PASSWORD_LENGTH:
            raise ValueError(f"Password length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}")
        
        # Build character set
        chars = ""
        if config.use_lowercase:
            chars += string.ascii_lowercase
        if config.use_uppercase:
            chars += string.ascii_uppercase
        if config.use_digits:
            chars += string.digits
        if config.use_symbols:
            chars += config.custom_symbols if config.custom_symbols else DEFAULT_SYMBOLS
        
        # Remove ambiguous characters if requested
        if config.exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in AMBIGUOUS_CHARS)
        
        if not chars:
            raise ValueError("No characters available for password generation!")
        
        # Generate password
        password = ''.join(secrets.choice(chars) for _ in range(config.length))
        
        # Ensure complexity
        password = self._ensure_complexity(password, config, chars)
        
        return password
    
    def _ensure_complexity(self, password: str, config: PasswordConfig, chars: str) -> str:
        """Ensure password contains at least one character from each selected type"""
        password_list = list(password)
        
        if config.use_lowercase and not any(c in string.ascii_lowercase for c in password):
            password_list[secrets.randbelow(len(password_list))] = secrets.choice(string.ascii_lowercase)
        
        if config.use_uppercase and not any(c in string.ascii_uppercase for c in password):
            password_list[secrets.randbelow(len(password_list))] = secrets.choice(string.ascii_uppercase)
        
        if config.use_digits and not any(c in string.digits for c in password):
            password_list[secrets.randbelow(len(password_list))] = secrets.choice(string.digits)
        
        if config.use_symbols:
            symbols = config.custom_symbols if config.custom_symbols else DEFAULT_SYMBOLS
            if config.exclude_ambiguous:
                symbols = ''.join(c for c in symbols if c not in AMBIGUOUS_CHARS)
            if symbols and not any(c in symbols for c in password):
                password_list[secrets.randbelow(len(password_list))] = secrets.choice(symbols)
        
        return ''.join(password_list)
    
    def generate_passphrase(
        self, num_words: int = 4, separator: str = "-",
        capitalize: bool = True, add_number: bool = True
    ) -> str:
        """Generate a memorable passphrase"""
        words = [secrets.choice(self.PASSPHRASE_WORDS) for _ in range(num_words)]
        
        if capitalize:
            words = [w.capitalize() for w in words]
        
        passphrase = separator.join(words)
        
        if add_number:
            passphrase += separator + str(secrets.randbelow(9999)).zfill(4)
        
        return passphrase
    
    def generate_pin(self, length: int = 6) -> str:
        """Generate a numeric PIN code"""
        return ''.join(secrets.choice(string.digits) for _ in range(length))
    
    def check_password_strength(self, password: str) -> Tuple[int, str]:
        """Evaluate password strength, returns (score 0-100, level string)"""
        score = 0
        
        # Length scoring
        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 20
        elif length >= 8:
            score += 10
        else:
            score += max(0, length * 1.25)
        
        # Character variety
        if any(c in string.ascii_lowercase for c in password):
            score += 10
        if any(c in string.ascii_uppercase for c in password):
            score += 10
        if any(c in string.digits for c in password):
            score += 10
        if any(c in DEFAULT_SYMBOLS for c in password):
            score += 15
        
        # Complexity bonus
        if length >= 12 and len(set(password)) >= length * 0.7:
            score += 15
        
        # Entropy bonus
        if len(set(password)) > length * 0.8:
            score += 10
        
        # Common password penalty
        common = ["password", "123456", "12345678", "qwerty", "abc123"]
        if password.lower() in common:
            score = 0
        
        # Determine strength level
        if score >= 80:
            level = _("Very Strong")
        elif score >= 60:
            level = _("Strong")
        elif score >= 40:
            level = _("Medium")
        elif score >= 20:
            level = _("Weak")
        else:
            level = _("Very Weak")
        
        return min(100, score), level
