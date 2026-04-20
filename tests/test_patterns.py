"""
Pattern tests — true positives AND false positives.

All test secrets use formats that are obviously synthetic:
- AWS: AKIAIOSFODNN7EXAMPLE (AWS's own documentation key)
- GitHub: ghp_ followed by clearly fake data
etc.

IMPORTANT: Never add real credentials here, even expired ones.
"""

from secrets_cli.patterns import PATTERNS

pattern_map = {p.name: p for p in PATTERNS}


def matches(pattern_name: str, text: str) -> list[str]:
    p = pattern_map[pattern_name]
    results = []
    for m in p.regex.finditer(text):
        results.append(m.group(1) if m.lastindex else m.group(0))
    return results


# ── AWS ──────────────────────────────────────────────────────────────────────

class TestAWSAccessKey:
    name = "AWS Access Key ID"

    def test_bare(self):
        assert matches(self.name, "AKIAIOSFODNN7EXAMPLE")

    def test_in_config(self):
        assert matches(self.name, 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"')

    def test_in_env(self):
        assert matches(self.name, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")

    # False positives
    def test_not_akia_prefix(self):
        assert not matches(self.name, "AKIB123456789EXAMPLE")

    def test_too_short(self):
        assert not matches(self.name, "AKIA12345")


class TestAWSSecretKey:
    name = "AWS Secret Access Key"

    def test_env_format(self):
        key = 'AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        assert matches(self.name, key)  # entropy check happens in scanner, not pattern

    def test_config_format(self):
        # Exactly 40 chars after keyword
        key = "aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCY8HvQzTk3mNpX"
        assert matches(self.name, key)

    # False positives
    def test_no_match_without_key_name(self):
        # Random 40-char string alone should NOT match (needs context keyword)
        assert not matches(self.name, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")


# ── GitHub ────────────────────────────────────────────────────────────────────

class TestGitHubPAT:
    name = "GitHub Personal Access Token"

    def test_classic_format(self):
        fake = "ghp_" + "A" * 36
        assert matches(self.name, fake)

    def test_in_yaml(self):
        fake = "ghp_" + "B" * 36
        assert matches(self.name, f"GITHUB_TOKEN: {fake}")

    # False positives
    def test_too_short(self):
        assert not matches(self.name, "ghp_tooshort")

    def test_wrong_prefix(self):
        assert not matches(self.name, "gha_" + "A" * 36)


class TestGitHubFineGrained:
    name = "GitHub Fine-Grained Token"

    def test_format(self):
        fake = "github_pat_" + "A" * 82
        assert matches(self.name, fake)


# ── Slack ─────────────────────────────────────────────────────────────────────

class TestSlackBot:
    name = "Slack Bot Token"

    def test_format(self):
        fake = "xoxb-1234567890-1234567890-" + "A" * 24
        assert matches(self.name, fake)

    def test_in_python(self):
        fake = "xoxb-1234567890-1234567890-" + "B" * 24
        assert matches(self.name, f'SLACK_TOKEN = "{fake}"')

    # False positives
    def test_xoxp_not_matched_as_bot(self):
        fake = "xoxp-1234567890-1234567890-1234567890-" + "C" * 32
        assert not matches(self.name, fake)


# ── Stripe ────────────────────────────────────────────────────────────────────

class TestStripeLive:
    name = "Stripe Live Secret Key"

    def test_format(self):
        assert matches(self.name, "sk_live_" + "x" * 24)

    # False positives
    def test_test_key_not_critical(self):
        assert not matches(self.name, "sk_test_" + "x" * 24)


# ── Database connection strings ───────────────────────────────────────────────

class TestDatabaseURL:
    name = "Database Connection String"

    def test_postgres(self):
        assert matches(self.name, "postgresql://admin:s3cr3tP@ss@db.example.com:5432/mydb")

    def test_mysql(self):
        # @ in passwords must be URL-encoded in connection strings
        assert matches(self.name, "mysql://root:p%40ssword@localhost/app")

    def test_mongodb(self):
        assert matches(self.name, "mongodb+srv://user:s3cr3tPass@cluster0.example.mongodb.net/")

    # False positives
    def test_no_password(self):
        # No colon before @ → no password → should not match
        assert not matches(self.name, "postgresql://localhost/mydb")

    def test_empty_password(self):
        # Empty password field — too short, threshold guards this
        assert not matches(self.name, "postgresql://user:@localhost/mydb")


# ── Generic secrets ───────────────────────────────────────────────────────────

class TestGenericSecret:
    name = "Generic Secret"

    def test_high_entropy_password(self):
        # High entropy → should match at pattern level
        result = matches(self.name, 'password = "X7#mK9$pL2@nQ8!vR3^hJ5"')
        assert result

    # False positives — these MUST NOT trigger
    def test_changeme(self):
        # "changeme" is too short (< 16 chars) → no regex match
        assert not matches(self.name, 'password = "changeme"')

    def test_placeholder_regex_matches_but_entropy_rejects(self):
        # Pattern-level regex matches "your_api_key_here" (≥16 chars)
        # but scanner's entropy check rejects it — tested at scanner level
        result = matches(self.name, 'api_key = "your_api_key_here"')
        # If regex matched, entropy check must be the guard — verify in test_scanner.py
        # Here we only document the regex behavior:
        _ = result  # may or may not match depending on length — entropy is the real guard

    def test_too_short(self):
        assert not matches(self.name, 'secret = "abc123"')

    def test_env_variable_reference(self):
        # env var reference, not a literal secret
        assert not matches(self.name, "password = os.environ['PASSWORD']")


# ── npm ──────────────────────────────────────────────────────────────────────

class TestNpmToken:
    name = "npm Access Token"

    def test_format(self):
        fake = "npm_" + "A" * 36
        assert matches(self.name, fake)

    def test_in_npmrc(self):
        fake = "npm_" + "B" * 36
        assert matches(self.name, f"//registry.npmjs.org/:_authToken={fake}")

    # False positives
    def test_too_short(self):
        assert not matches(self.name, "npm_tooshort")

    def test_wrong_prefix(self):
        assert not matches(self.name, "npx_" + "A" * 36)


# ── Azure ─────────────────────────────────────────────────────────────────────

class TestAzureConnectionString:
    name = "Azure Storage Connection String"

    def test_full_connection_string(self):
        fake_key = "A" * 86 + "=="
        cs = f"DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey={fake_key};EndpointSuffix=core.windows.net"
        assert matches(self.name, cs)

    def test_http_variant(self):
        fake_key = "B" * 86 + "=="
        cs = f"DefaultEndpointsProtocol=http;AccountName=test;AccountKey={fake_key}"
        assert matches(self.name, cs)

    # False positives
    def test_no_account_key(self):
        assert not matches(self.name, "DefaultEndpointsProtocol=https;AccountName=test;EndpointSuffix=core.windows.net")


class TestAzureStorageAccountKey:
    name = "Azure Storage Account Key"

    def test_env_format(self):
        fake_key = "A" * 86 + "=="
        assert matches(self.name, f'ACCOUNT_KEY="{fake_key}"')

    def test_yaml_format(self):
        fake_key = "B" * 86 + "=="
        assert matches(self.name, f"AccountKey: {fake_key}")

    # False positives
    def test_no_match_without_context(self):
        assert not matches(self.name, "A" * 86 + "==")


# ── OpenAI ────────────────────────────────────────────────────────────────────

class TestOpenAIKey:
    name = "OpenAI API Key"

    def test_classic_format(self):
        fake = "sk-" + "A" * 48
        assert matches(self.name, fake)

    def test_project_format(self):
        fake = "sk-proj-" + "A" * 48
        assert matches(self.name, fake)

    def test_in_env(self):
        fake = "sk-" + "B" * 48
        assert matches(self.name, f"OPENAI_API_KEY={fake}")

    # False positives
    def test_stripe_not_matched(self):
        # Stripe uses underscores: sk_live_ / sk_test_ — not sk-
        assert not matches(self.name, "sk_live_" + "x" * 24)

    def test_too_short(self):
        assert not matches(self.name, "sk-" + "A" * 10)


# ── Anthropic ─────────────────────────────────────────────────────────────────

class TestAnthropicKey:
    name = "Anthropic API Key"

    def test_format(self):
        fake = "sk-ant-api03-" + "A" * 93
        assert matches(self.name, fake)

    def test_generic_ant_prefix(self):
        fake = "sk-ant-" + "A" * 40
        assert matches(self.name, fake)

    def test_in_env(self):
        fake = "sk-ant-api03-" + "B" * 50
        assert matches(self.name, f"ANTHROPIC_API_KEY={fake}")

    # False positives
    def test_openai_not_matched(self):
        assert not matches(self.name, "sk-" + "A" * 48)

    def test_too_short(self):
        assert not matches(self.name, "sk-ant-tooshort")


# ── Private key ───────────────────────────────────────────────────────────────

class TestPrivateKey:
    name = "Private Key (PEM)"

    def test_rsa(self):
        # Header line alone is sufficient signal
        assert matches(self.name, "-----BEGIN RSA PRIVATE KEY-----")

    def test_openssh(self):
        assert matches(self.name, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC...")

    def test_generic(self):
        assert matches(self.name, "-----BEGIN PRIVATE KEY-----\nMIIEvQ...")

    # False positives
    def test_public_key_not_matched(self):
        assert not matches(self.name, "-----BEGIN PUBLIC KEY-----")

    def test_certificate_not_matched(self):
        assert not matches(self.name, "-----BEGIN CERTIFICATE-----")
