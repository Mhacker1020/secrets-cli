# nosecrets

**Scan for hardcoded secrets before they reach your repository.**

Zero runtime dependencies. Runs as a pre-commit hook or standalone CLI. Designed for developers who want a lightweight, auditable secrets scanner without pulling in a 20MB Go binary or a heavy Python dependency tree.

```
$ secrets scan

  [CRITICAL]  src/config.py:14
               AWS Access Key ID: AKIA************MPLE

  [HIGH]  deploy/docker-compose.yml:8
           Database Connection String: postg****alhost

  Found 2 potential secret(s): 1 CRITICAL, 1 HIGH

  To suppress a finding:
    Inline:  add  # nosecrets  at end of line
    Global:  add path to .secretsignore
```

---

## Why nosecrets?

| Feature | gitleaks | truffleHog | detect-secrets | **nosecrets** |
|---------|:--------:|:----------:|:--------------:|:-------------:|
| Git history scan | ✅ | ✅ | ❌ | ✅ |
| SARIF output | ✅ | ✅ | ❌ | ✅ |
| Baseline file | ❌ | ❌ | ✅ | ✅ |
| Zero runtime deps | ❌ Go binary | ❌ | ❌ | ✅ |
| `pip install` | ❌ | ❌ | ✅ | ✅ |
| False positive handling | weak | weak | ok | **best-in-class** |

The only zero-dependency Python tool with git history scanning, SARIF output, and baseline suppression — all three.

---

## Install

```bash
pip install nosecrets
```

Requires Python 3.12+.

---

## Usage

```bash
# Scan current directory
secrets scan

# Scan a specific path
secrets scan src/

# Scan only staged files (pre-commit)
secrets scan --staged

# Output formats
secrets scan --format text    # coloured output (default)
secrets scan --format json    # JSON for CI pipelines
secrets scan --format sarif   # SARIF for GitHub Advanced Security

# Only report HIGH and above
secrets scan --severity high

# Scan entire git history (finds secrets in deleted commits too)
secrets scan --history
secrets scan --history --max-commits 50

# Baseline — skip known findings, report only new ones
secrets baseline              # write .nosecrets-baseline.json
secrets scan --baseline       # compare against baseline

# Install pre-commit hook
secrets init

# Remove hook
secrets uninstall
```

---

## Pre-commit hook

```bash
secrets init
```

Installs a git hook that runs `secrets scan --staged` before every commit. If a CRITICAL or HIGH secret is found, the commit is blocked.

To remove:

```bash
secrets uninstall
```

---

## What it detects

| Severity | Pattern |
|----------|---------|
| CRITICAL | RSA / EC / OpenSSH private keys |
| CRITICAL | AWS Access Key ID (`AKIA...`) |
| CRITICAL | AWS Secret Access Key (with keyword context) |
| CRITICAL | Azure Storage connection string (`DefaultEndpointsProtocol=...`) |
| CRITICAL | Azure Storage Account Key (with keyword context) |
| CRITICAL | OpenAI API Key (`sk-...`, `sk-proj-...`) |
| CRITICAL | Anthropic API Key (`sk-ant-...`) |
| CRITICAL | Stripe Live Secret Key (`sk_live_...`) |
| HIGH | GitHub Tokens (`ghp_`, `github_pat_`, `gho_`, `ghs_`, `ghr_`) |
| HIGH | GitLab Personal Access Token (`glpat-...`) |
| HIGH | npm Access Token (`npm_...`) |
| HIGH | Google API Key (`AIza...`) |
| HIGH | Slack Bot / User / Webhook tokens |
| HIGH | SendGrid API Key (`SG....`) |
| HIGH | Twilio Account SID (`AC...`) |
| HIGH | Database connection strings with credentials |
| MEDIUM | JSON Web Tokens (hardcoded) |
| MEDIUM | Generic secrets (high-entropy `api_key`, `password`, `token` values) |

---

## False positive prevention

Two-layer defence against false positives:

**1. Placeholder detection** — values like `"changeme"`, `"your_api_key_here"`, `${SECRET}`, `{{token}}` are never flagged regardless of pattern match.

**2. Shannon entropy filter** — generic patterns (password, api_key, token) only trigger when the value has sufficient entropy. `password = "test123"` is ignored. `password = "X7#mK9$pL2@nQ8!"` is flagged.

High-confidence patterns (AWS `AKIA...`, GitHub `ghp_...`, etc.) skip entropy filtering because their fixed prefix already guarantees low false positive rate.

---

## Suppression

**Inline — suppress a single line:**

```python
api_key = "AKIAIOSFODNN7EXAMPLE"  # nosecrets
```

**File/directory — `.secretsignore`:**

```
# gitignore-style syntax
tests/fixtures/
*.example
legacy_config.py
```

Copy `.secretsignore.example` from the repo as a starting point.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `--fail-on` threshold |
| `1` | One or more findings at or above threshold |

Default `--fail-on` is `high`. Change with `--fail-on critical` to only block on critical findings.

---

## CI integration

```yaml
# GitHub Actions — basic
- name: Scan for secrets
  run: |
    pip install nosecrets
    secrets scan --severity medium
```

```yaml
# GitHub Actions — SARIF upload (shows findings inline in PR diffs)
- name: Scan for secrets
  run: |
    pip install nosecrets
    secrets scan --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

```yaml
# GitHub Actions — baseline (report only new secrets)
- name: Scan for new secrets
  run: |
    pip install nosecrets
    secrets scan --baseline  # requires .nosecrets-baseline.json committed to repo
```

---

## Philosophy

> "A secrets scanner that leaks its own secrets is not a secrets scanner."

- **Zero runtime dependencies** — stdlib only, fully auditable
- **Staged scanning** reads from the git index (`git show :<path>`), not the working tree — you scan exactly what will be committed
- **Secrets are never printed in full** — output always redacts the middle portion
- **Pattern quality over quantity** — 20 well-tested patterns beat 500 noisy ones

---

## License

MIT
