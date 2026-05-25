# Secrets Detection Reference

## Pattern Library

### API Keys & Tokens
```regex
# Generic API Key
(?i)(api[_-]?key|apikey|secret[_-]?key|secretkey|access[_-]?key|token)\s*[=:]\s*['\"][a-zA-Z0-9_\-=]{16,}['\"]

# AWS
AKIA[0-9A-Z]{16}
(?i)aws[_-]?(access[_-]?key[_-]?id|secret[_-]?access[_-]?key)\s*[=:]\s*['\"][A-Za-z0-9/+=]{20,40}['\"]

# Azure
(?i)azure[_-]?(key|connection[_-]?string|storage[_-]?key|subscription[_-]?key)

# GCP
AIza[0-9A-Za-z\-_]{35}  # API Key
"type": "service_account"  # Service Account JSON

# GitHub
ghp_[A-Za-z0-9]{36}
gho_[A-Za-z0-9]{36}
ghu_[A-Za-z0-9]{36}
ghs_[A-Za-z0-9]{36}
ghr_[A-Za-z0-9]{36}

# GitLab
glpat-[A-Za-z0-9\-_]{20,35}

# Slack
xox[baprs]-[A-Za-z0-9-]{10,}

# Discord
https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+

# JWT
eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}

# Stripe
(?i)sk_live_[0-9a-zA-Z]{24,}
(?i)pk_live_[0-9a-zA-Z]{24,}
(?i)sk_test_[0-9a-zA-Z]{24,}

# npm
//registry.npmjs.org/:_authToken=[A-Za-z0-9\-_]{36}

# Private Keys
-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----
-----BEGIN CERTIFICATE-----

# Connection Strings
(?i)(mysql|postgres|mongodb|redis|amqp|rabbitmq)://[^:]+:[^@]+@

# Passwords
(?i)password\s*[=:]\s*['\"][^'\"]{8,}['\"]
```

## Entropy Analysis

When regex doesn't catch it (custom/non-standard secrets):

```python
import math

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy bits per character."""
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum((f/len(s)) * math.log2(f/len(s)) for f in freq.values())

# Flag if: entropy > 4.5 AND len > 14 AND in variable assignment
# This catches custom API keys, tokens, and secrets not covered by regex
```

## File Types to Scan

| Priority | Files | Reason |
|---|---|---|
| Critical | `.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `credentials` | Direct secrets |
| High | `*.py`, `*.js`, `*.ts`, `*.java`, `*.cs`, `*.go`, `*.rs` | Hardcoded secrets in code |
| High | `requirements.txt`, `package.json`, `Cargo.toml`, `go.mod` | Dependency tokens |
| Medium | `*.yaml`, `*.yml`, `*.json`, `*.xml`, `*.config`, `*.ini`, `*.cfg` | Config files |
| Medium | `*.md`, `*.rst`, `*.txt` | Documentation leaks |
| Low | `*.log`, `*.sql` | Historical data |

## Git History Scanning

```bash
# Scan all commits in git history for secrets
git log --all --full-history --diff-filter=A -- '*.py' '*.js' '*.env'

# Check for committed secrets that were later removed
# (secrets in git history are compromised forever)
```

## Prevention Patterns

```python
# BAD — Hardcoded
API_KEY = "sk-live-abc123def456ghi789jkl012"

# GOOD — Environment variable
import os
API_KEY = os.environ.get("STRIPE_SECRET_KEY")
if not API_KEY:
    raise RuntimeError("STRIPE_SECRET_KEY not set")

# BETTER — Secrets manager
from vault import get_secret
API_KEY = get_secret("stripe/live/api_key")
```
