"""
Secret patterns registry.

Each pattern has:
  - name: display name
  - regex: compiled pattern (must have one capture group for the secret value)
  - severity: CRITICAL / HIGH / MEDIUM / INFO
  - entropy_check: whether to apply Shannon entropy filter to captured group
  - entropy_charset: "base64" | "hex" | "generic"
  - description: what was found

High-confidence patterns (unique prefixes, fixed length) do NOT use entropy_check.
Generic patterns (api_key = "...") MUST use entropy_check to avoid false positives.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern[str]
    severity: str
    description: str
    entropy_check: bool = False
    entropy_charset: str = "generic"


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


PATTERNS: list[Pattern] = [
    # ── Private keys (CRITICAL, no entropy check needed — header is unique) ──
    Pattern(
        name="Private Key (PEM)",
        regex=_r(
            r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?"
            r"PRIVATE KEY(?:-----|[ ]BLOCK-----)[-]*)"
        ),
        severity="CRITICAL",
        description="Private key detected in file",
    ),

    # ── AWS (CRITICAL — fixed prefix + fixed length = high confidence) ──
    Pattern(
        name="AWS Access Key ID",
        regex=_r(r"(AKIA[0-9A-Z]{16})"),
        severity="CRITICAL",
        description="AWS Access Key ID",
    ),
    Pattern(
        name="AWS Secret Access Key",
        regex=_r(
            r'(?:aws_secret(?:_access)?_key|AWS_SECRET(?:_ACCESS)?_KEY)\s*[=:]\s*["\']?([A-Za-z0-9/+]{40})["\']?'
        ),
        severity="CRITICAL",
        description="AWS Secret Access Key",
        entropy_check=True,
        entropy_charset="base64",
    ),

    # ── GitHub (HIGH — unique prefixes) ──
    Pattern(
        name="GitHub Personal Access Token",
        regex=_r(r"(ghp_[a-zA-Z0-9]{36})"),
        severity="HIGH",
        description="GitHub Personal Access Token (classic)",
    ),
    Pattern(
        name="GitHub Fine-Grained Token",
        regex=_r(r"(github_pat_[a-zA-Z0-9_]{82})"),
        severity="HIGH",
        description="GitHub Fine-Grained Personal Access Token",
    ),
    Pattern(
        name="GitHub OAuth/App Token",
        regex=_r(r"(gh[osr]_[a-zA-Z0-9]{36})"),
        severity="HIGH",
        description="GitHub OAuth/Server/Refresh Token",
    ),

    # ── GitLab (HIGH) ──
    Pattern(
        name="GitLab Personal Access Token",
        regex=_r(r"(glpat-[a-zA-Z0-9\-_]{20})"),
        severity="HIGH",
        description="GitLab Personal Access Token",
    ),

    # ── Google (HIGH) ──
    Pattern(
        name="Google API Key",
        regex=_r(r"(AIza[0-9A-Za-z\-_]{35})"),
        severity="HIGH",
        description="Google API Key",
    ),

    # ── Slack (HIGH) ──
    Pattern(
        name="Slack Bot Token",
        regex=_r(r"(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})"),
        severity="HIGH",
        description="Slack Bot Token",
    ),
    Pattern(
        name="Slack User Token",
        regex=_r(r"(xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32})"),
        severity="HIGH",
        description="Slack User OAuth Token",
    ),
    Pattern(
        name="Slack Webhook URL",
        regex=_r(r"(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,})"),
        severity="HIGH",
        description="Slack Incoming Webhook URL",
    ),

    # ── Stripe (HIGH/CRITICAL split by test vs live) ──
    Pattern(
        name="Stripe Live Secret Key",
        regex=_r(r"(sk_live_[a-zA-Z0-9]{24,})"),
        severity="CRITICAL",
        description="Stripe Live Secret Key",
    ),
    Pattern(
        name="Stripe Test Secret Key",
        regex=_r(r"(sk_test_[a-zA-Z0-9]{24,})"),
        severity="MEDIUM",
        description="Stripe Test Secret Key (not production but still a credential)",
    ),

    # ── SendGrid (HIGH) ──
    Pattern(
        name="SendGrid API Key",
        regex=_r(r"(SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})"),
        severity="HIGH",
        description="SendGrid API Key",
    ),

    # ── Twilio (HIGH) ──
    Pattern(
        name="Twilio Account SID",
        regex=_r(r"(AC[a-f0-9]{32})"),
        severity="HIGH",
        description="Twilio Account SID",
    ),

    # ── Database connection strings (HIGH — contains credentials) ──
    Pattern(
        name="Database Connection String",
        regex=_r(
            r"((?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|amqp|amqps)://[^:@\s]+:[^@\s]{4,}@[^\s\"']{4,})"
        ),
        severity="HIGH",
        description="Database connection string with embedded credentials",
    ),

    # ── JWT (MEDIUM — real tokens should not be hardcoded) ──
    Pattern(
        name="JSON Web Token",
        regex=_r(r"(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})"),
        severity="MEDIUM",
        description="Hardcoded JWT — use environment variables",
        entropy_check=True,
        entropy_charset="base64",
    ),

    # ── Generic high-entropy secrets (MEDIUM — entropy filter mandatory) ──
    Pattern(
        name="Generic Secret",
        regex=_r(
            r'(?:password|passwd|pwd|secret|api_?key|auth_?token|access_?token|private_?key)'
            r'\s*[=:]\s*["\']([a-zA-Z0-9+/=_\-!@#$%^&*]{16,})["\']'
        ),
        severity="MEDIUM",
        description="Potential hardcoded secret — verify manually",
        entropy_check=True,
        entropy_charset="generic",
    ),

    # ── .env files committed (INFO) ──
    # Handled at file level in scanner, not here.
]
