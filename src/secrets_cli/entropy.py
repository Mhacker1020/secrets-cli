import math
from collections import Counter

# Thresholds tuned against common fake values ("changeme", "your_key_here", etc.)
# Real secrets typically score above these values.
ENTROPY_THRESHOLD_BASE64 = 4.0   # base64-alphabet secrets (API keys, tokens)
ENTROPY_THRESHOLD_HEX = 3.2      # hex secrets
ENTROPY_THRESHOLD_GENERIC = 3.5  # mixed-charset secrets


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_like_placeholder(value: str) -> bool:
    """Return True for obvious placeholders that should never trigger."""
    low = value.lower()
    placeholders = (
        "changeme", "change_me", "your_", "replace_", "insert_",
        "example", "placeholder", "dummy", "fake", "test", "sample",
        "xxxxxxxx", "aaaaaaaa", "1234567890", "password123",
        "todo", "fixme", "secret_here", "token_here", "key_here",
        "<", ">", "${", "%(", "{{",
    )
    return any(p in low for p in placeholders)


def is_high_entropy(value: str, charset: str = "generic") -> bool:
    if looks_like_placeholder(value):
        return False
    entropy = shannon_entropy(value)
    thresholds = {
        "base64": ENTROPY_THRESHOLD_BASE64,
        "hex": ENTROPY_THRESHOLD_HEX,
        "generic": ENTROPY_THRESHOLD_GENERIC,
    }
    return entropy >= thresholds.get(charset, ENTROPY_THRESHOLD_GENERIC)
