from secrets_cli.entropy import is_high_entropy, looks_like_placeholder, shannon_entropy


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_uniform_string(self):
        # All same chars → entropy 0
        assert shannon_entropy("aaaaaaaaaa") == 0.0

    def test_real_api_key_has_high_entropy(self):
        # Simulate realistic base64-ish key
        key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert shannon_entropy(key) > 4.0

    def test_placeholder_has_low_entropy(self):
        assert shannon_entropy("changeme") < 3.5
        assert shannon_entropy("your_key_here") < 3.5


class TestLooksLikePlaceholder:
    def test_changeme(self):
        assert looks_like_placeholder("changeme")

    def test_your_prefix(self):
        assert looks_like_placeholder("your_api_key")

    def test_example(self):
        assert looks_like_placeholder("example_secret_123")

    def test_template_syntax(self):
        assert looks_like_placeholder("${API_KEY}")
        assert looks_like_placeholder("{{secret}}")

    def test_real_key_not_placeholder(self):
        assert not looks_like_placeholder("wJalrXUtnFEMI/K7MDENGbPx")


class TestIsHighEntropy:
    def test_real_aws_secret(self):
        # AWS secret format: 40 chars, high entropy — no placeholder words
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY8HvQzTk3mN"
        assert is_high_entropy(secret, "base64")

    def test_placeholder_rejected(self):
        assert not is_high_entropy("changeme12345678", "generic")

    def test_your_key_rejected(self):
        assert not is_high_entropy("your_api_key_here_1234", "generic")

    def test_low_entropy_value(self):
        # Repeated pattern → low entropy
        assert not is_high_entropy("abcdabcdabcdabcdabcd", "generic")

    def test_template_variable_rejected(self):
        assert not is_high_entropy("${SECRET_KEY}", "generic")
