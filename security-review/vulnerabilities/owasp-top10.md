# OWASP Top 10 (2021) — Deep Reference

## A01: Broken Access Control
**CWE Mapping**: CWE-22, CWE-284, CWE-285, CWE-639, CWE-862, CWE-863

### Detection
- No authorization check on authenticated endpoints
- Sequential/enumerable object IDs without ownership validation
- Role checks in client-side code only
- CORS allowing credentialed requests from arbitrary origins
- Direct file path access without validation

### Fix Pattern
```python
# DECORATOR-BASED (Django/Flask)
@login_required
@user_passes_test(lambda u: u.is_admin)
def admin_view(request): ...

# OBJECT-LEVEL (FastAPI)
@router.get("/users/{user_id}")
async def get_user(user_id: int, current_user = Depends(get_current_user)):
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(403)
    return await get_user_by_id(user_id)
```

---

## A02: Cryptographic Failures
**CWE Mapping**: CWE-256, CWE-257, CWE-311, CWE-312, CWE-319, CWE-326, CWE-327, CWE-328

### Detection
- MD5, SHA-1 for passwords or integrity
- AES-ECB mode (deterministic, pattern-leaking)
- `random` module (not `secrets`) for cryptographic values
- TLS < 1.2
- Hardcoded keys or certificates
- Self-signed certificates in production

### Fix Pattern
```python
# PASSWORD HASHING
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# ENCRYPTION (AES-GCM)
from cryptography.fernet import Fernet
key = Fernet.generate_key()
cipher = Fernet(key)
encrypted = cipher.encrypt(data)
decrypted = cipher.decrypt(encrypted)
```

---

## A03: Injection
**CWE Mapping**: CWE-77, CWE-78, CWE-89, CWE-90, CWE-94, CWE-95, CWE-116, CWE-917

### Detection Patterns by Language
See agent for full per-language detection signatures.

### Fix Principle
**NEVER** concatenate user input into query strings, shell commands, or template strings. ALWAYS use:
- Parameterized queries for SQL
- `execFile` / array args for shell
- Template variables for render engines
- Object references for NoSQL

---

## A04: Insecure Design
**CWE Mapping**: CWE-73, CWE-183, CWE-209, CWE-213, CWE-362, CWE-441

### Detection
- No rate limiting on auth endpoints
- Price/quantity sent from client without server validation
- Workflow state stored in URL params
- Missing account lockout
- Password policy not enforced server-side
- MFA not available for sensitive operations

---

## A05: Security Misconfiguration
**CWE Mapping**: CWE-16, CWE-209, CWE-215, CWE-260, CWE-315, CWE-520, CWE-526

### Detection
- `DEBUG=True` in production
- Directory listing enabled
- Default admin credentials
- Unnecessary HTTP methods enabled (PUT, DELETE)
- Server version in headers
- Verbose error pages
- Missing security headers

### Required Headers
```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

---

## A06: Vulnerable & Outdated Components
**CWE Mapping**: CWE-937, CWE-1035, CWE-1104

### Detection
- Parse lockfiles against NVD / GitHub Advisory Database
- Check for end-of-life runtimes (Python 2, Node 14, Java 8)
- Identify unmaintained packages (no commits in 2+ years)
- Check for known typo-squatting packages

---

## A07: Identification & Authentication Failures
**CWE Mapping**: CWE-255, CWE-259, CWE-287, CWE-288, CWE-290, CWE-306, CWE-307, CWE-308, CWE-521, CWE-613, CWE-640, CWE-798

### JWT Security
```python
# VULNERABLE
jwt.decode(token, algorithms=["none"])           # CVE-2015-9235
jwt.decode(token, verify=False)                  # No verification
jwt.decode(token, "secret", algorithms=["HS256"])  # Weak secret

# SECURE
jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"],
           audience="https://api.example.com",
           issuer="https://auth.example.com",
           options={"require": ["exp", "iat", "nbf"]})
```

---

## A08: Software & Data Integrity Failures
**CWE Mapping**: CWE-345, CWE-353, CWE-426, CWE-494, CWE-502, CWE-565, CWE-784, CWE-829

### Deserialization Risk by Language
| Language | Dangerous Functions | Severity |
|---|---|---|
| Python | `pickle.loads()`, `yaml.load()` | CRITICAL (RCE) |
| Java | `ObjectInputStream.readObject()` | CRITICAL (RCE) |
| Node | `JSON.parse()` + `__proto__` | HIGH (PP) |
| PHP | `unserialize()` | CRITICAL (RCE) |
| Ruby | `Marshal.load()` | CRITICAL (RCE) |

---

## A09: Security Logging & Monitoring Failures
**CWE Mapping**: CWE-117, CWE-223, CWE-532, CWE-778

### Detection
- No audit log for auth events
- Passwords, tokens, or PII in logs
- No centralized logging
- No alerting on suspicious patterns
- Logs without integrity protection

---

## A10: SSRF
**CWE Mapping**: CWE-918

### Detection
- `requests.get(url)` where `url` comes from user input
- `fetch(url)` with user-supplied URL
- `HttpClient.GetAsync(uri)` with user-supplied URI
- URL preview/image fetch features

### Cloud Metadata Endpoints
```
AWS:     http://169.254.169.254/latest/meta-data/
GCP:     http://metadata.google.internal/computeMetadata/v1/
Azure:   http://169.254.169.254/metadata/instance?api-version=2021-02-01
DigitalOcean: http://169.254.169.254/metadata/v1.json
```
