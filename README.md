
███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝

██████╗ ███████╗██╗   ██╗██╗███████╗██╗    ██╗
██╔══██╗██╔════╝██║   ██║██║██╔════╝██║    ██║
██████╔╝█████╗  ██║   ██║██║█████╗  ██║ █╗ ██║
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║██╔══╝  ██║███╗██║
██║  ██║███████╗ ╚████╔╝ ██║███████╗╚███╔███╔╝
╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚═╝╚══════╝ ╚══╝╚══╝

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/SAST-Full-6C5CE7?style=flat-square" alt="SAST"></a>
  <a href="#"><img src="https://img.shields.io/badge/DAST-Patterns-E17055?style=flat-square" alt="DAST"></a>
  <a href="#"><img src="https://img.shields.io/badge/OWASP-Top%2010-D63031?style=flat-square" alt="OWASP"></a>
  <a href="#"><img src="https://img.shields.io/badge/CWE-Top%2025-0984E3?style=flat-square" alt="CWE"></a>
  <a href="#"><img src="https://img.shields.io/badge/Secrets-Detection-00B894?style=flat-square" alt="Secrets"></a>
  <a href="#"><img src="https://img.shields.io/badge/Languages-12%2B-FDCB6E?style=flat-square" alt="Languages"></a>
  <a href="#"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/OpenCode-Agent-6C5CE7?style=flat-square" alt="OpenCode"></a>
</p>

---

**Advanced AI red-team / white-hat security agent** for OpenCode. Performs deep, context-aware security analysis across 12+ languages with full OWASP Top 10, CWE Top 25, and SANS Top 25 coverage. Detects vulnerabilities, exploits them safely to verify, and fixes them with production-ready code.

Not a prompt wrapper — a complete security engineering framework compiled into an OpenCode agent. Contains real detection patterns, exploitation techniques, remediation templates, attack libraries, and CI/CD integration patterns.

---

## Table of Contents

- [What Makes This Different](#what-makes-this-different)
- [Capabilities](#capabilities)
- [Language Support](#language-support)
- [Standard Coverage](#standard-coverage)
- [Quick Start](#quick-start)
- [Agent Usage](#agent-usage)
- [Finding Format](#finding-format)
- [CI/CD Integration](#cicd-integration)
- [Repository Structure](#repository-structure)
- [References](#references)

---

## What Makes This Different

| Trait | Typical Security Agent | SecurityReview Agent |
|---|---|---|
| **Vulnerability Detection** | Prompt-level rules | 350+ detection patterns with code examples across 12+ languages |
| **Exploitation** | "Check for X" | Full exploitation payloads, attack chains, and safe verification commands |
| **Remediation** | "Use parameterized queries" | Production-ready code fix before/after in every language |
| **Reporting** | Text description | CVSS 3.1-scored, CWE-mapped, SARIF-compatible structured findings |
| **Integration** | Manual execution | Pre-commit hooks, GitHub Actions, GitLab CI, SARIF output |
| **Depth** | Surface scanning | Multi-phase methodology: recon → scanning → verification → exploitation → fix → report |
| **Secrets** | Basic regex | 30+ regex patterns + Shannon entropy analysis + git history scanning |
| **Attack Library** | None | SQL injection, XSS, SSRF, path traversal, JWT, OAuth, cloud metadata payloads |

---

## Capabilities

- **SAST (Static Analysis)**: Deep code scanning with language-specific vulnerability patterns
- **DAST Patterns**: Server-side exploitation verification templates (Nuclei, payload libraries)
- **Secrets Detection**: 30+ regex patterns + entropy-based analysis for custom secrets
- **SCA (Software Composition Analysis)**: Dependency vulnerability matching against known CVEs
- **Supply Chain Security**: Malicious package detection, typo-squatting, dependency confusion
- **Infrastructure Security**: Cloud metadata attacks, container escape, Kubernetes misconfigs
- **AI/ML Security**: Prompt injection, model extraction, adversarial input testing
- **Business Logic**: Race conditions, workflow bypasses, parameter tampering
- **Cryptographic Review**: Weak algorithms, key management, TLS configuration
- **Authentication Hardening**: JWT attacks, OAuth flows, session management, MFA review

### Analysis Phases

```
Phase 1: Reconnaissance
  ├── Stack identification (headers, errors, source maps)
  ├── Attack surface mapping (endpoints, auth, uploads)
  └── Dependency analysis (lockfiles, CVEs)

Phase 2: Automated Scanning
  ├── SAST (pattern matching + AST analysis)
  ├── Secrets (regex + entropy)
  └── SCA (version matching)

Phase 3: Verification
  ├── Exploitability confirmation
  ├── Attack chain mapping
  └── Bypass testing

Phase 4: Remediation
  ├── Production-ready fix
  ├── Regression test
  └── Performance/backwards-compat review

Phase 5: Reporting
  └── CVSS-scored, CWE-mapped, SARIF-compatible
```

---

## Language Support

| Language | Frameworks | Detection Depth |
|---|---|---|
| **Python** | Django, Flask, FastAPI | SQLi, SSTI, XSS, Command Injection, Mass Assignment, Pickle RCE |
| **JavaScript/TypeScript** | Node, React, Vue, Angular | XSS, Prototype Pollution, NoSQLi, Command Inj, eval, JWT |
| **Java** | Spring, Jakarta | SQLi, Path Traversal, Deserialization, XXE, Auth Bypass |
| **C#/.NET** | ASP.NET MVC, WebForms, Core | SQLi, XSS, Deserialization, Path Traversal, CSRF |
| **Go** | net/http, Gin, Echo | SQLi, Command Inj, Path Traversal, TLS misconfig |
| **Rust** | Actix, Axum, Rocket | Unsafe code, SQLi, Command Inj, Integer Overflow |
| **Solidity** | Hardhat, Foundry, Truffle | Reentrancy, Arithmetic, tx.origin, Flash Loans |
| **PHP** | Laravel, Symfony, WordPress | SQLi, XSS, Deserialization, File Inclusion |
| **Ruby** | Rails, Sinatra | SQLi, XSS, Mass Assignment, Command Inj |
| **Swift** | Vapor, iOS | Insecure storage, Network, Auth |
| **Kotlin** | Spring Boot, Ktor | Same as Java + coroutine vulnerabilities |
| **C/C++** | Native | Buffer overflow, Use-after-free, Format string |

---

## Standard Coverage

| Standard | Coverage |
|---|---|
| OWASP Top 10 (2021) | Full — A01 through A10 with detection, exploitation, and fix patterns |
| CWE Top 25 (2024) | All 25 — complete detection signatures per weakness |
| SANS Top 25 | Full mapping with code examples |
| OWASP ASVS Level 2 | V1-V14 architecture and verification requirements |
| OWASP API Security Top 10 | API-specific patterns: BOLA, mass assignment, rate limiting |
| OWASP Mobile Top 10 | Mobile-specific: insecure storage, untrusted inputs |
| NIST SP 800-53 | Mapped security controls |
| PCI DSS | Payment data security requirements |
| CVSS 3.1 | All findings scored with vector strings |

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/cryxservices-glitch/SecurityReviewAgent.git

# Use in any OpenCode project
@SecurityReview audit this codebase for vulnerabilities

# Or scan a specific file
@SecurityReview find vulnerabilities in src/api/users.py

# Or get a fix for a specific finding
@SecurityReview how to fix SQL injection in this Go handler
```

---

## Agent Usage

### Global Install

```bash
cp -r .opencode/agents/SecurityReview.md ~/.config/opencode/agents/
```

### Per-Project

The `.opencode/agents/` directory in this repo is pre-configured. OpenCode auto-detects agents in your project's `.opencode/agents/` folder.

### Commands

```
@SecurityReview audit <path>              — Full security audit of a codebase
@SecurityReview scan <file>               — Scan a specific file
@SecurityReview test <vuln-type> <file>   — Test for a specific vuln class
@SecurityReview fix <finding-id>          — Generate a fix for a previous finding
@SecurityReview exploit <vuln-type>       — Show exploitation payloads
@SecurityReview report                    — Generate structured report
@SecurityReview deps <path>               — Dependency vulnerability scan
@SecurityReview secrets <path>            — Secrets scan
```

### Depth Levels

| Depth | Use Case |
|---|---|
| **Quick** | Fast surface scan, dependency check |
| **Standard** | Full SAST + secrets + SCA (default) |
| **Deep** | Full analysis with exploitation verification |
| **Competitive** | Red-team style multi-vector attack simulation |

---

## Finding Format

Every finding follows the structured standard:

```
┌─────────────────────────────────────────────────────────┐
│ Title:       [CWE-89] SQL Injection in User Lookup      │
│ Severity:    Critical (10/10)                            │
│ CWE:         CWE-89, CWE-20                             │
│ OWASP:       A03:2021-Injection                         │
│ CVSS:        9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) │
│ File:        src/api/users.py:42                        │
│ Tool:        SecurityReview Agent                       │
├─────────────────────────────────────────────────────────┤
│ Description:                                             │
│ User input concatenated into SQL query without params.   │
├─────────────────────────────────────────────────────────┤
│ Vulnerable Code:                                         │
│   user = db.query(f"SELECT * FROM users WHERE id =      │
│                   {request.args.get('id')}")             │
├─────────────────────────────────────────────────────────┤
│ Exploitation:                                            │
│   GET /api/user?id=1 UNION SELECT * FROM credentials    │
│   Confirmed: boolean-based blind, 2s time-based delay   │
├─────────────────────────────────────────────────────────┤
│ Remediation:                                             │
│   user = db.query("SELECT * FROM users WHERE id = ?",   │
│                   [request.args.get('id')])              │
└─────────────────────────────────────────────────────────┘
```

Output is also available in SARIF format for GitHub Code Scanning integration.

---

## CI/CD Integration

### Pre-Commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: security-review
        name: Security Review
        entry: opencode run agent SecurityReview
        language: system
        types: [python, javascript, java, csharp, go, rust]
```

### GitHub Actions

```yaml
# .github/workflows/security-review.yml
name: Security Review
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Security Review
        run: |
          opencode run agent SecurityReview \
            --scan-dir . \
            --severity-threshold medium \
            --format sarif \
            --output security-report.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-report.sarif
```

---

## Repository Structure

```
SecurityReviewAgent/
+-- .opencode/
|   +-- agents/
|       +-- SecurityReview.md    # ★ The agent — full security engine
+-- security-review/             # Knowledge base framework
|   +-- vulnerabilities/
|   |   +-- owasp-top10.md       # OWASP Top 10 deep reference
|   |   +-- cwe-top25.md        # CWE Top 25 detection signatures
|   |   +-- language-specific.md # Per-language vuln patterns
|   |   +-- secrets.md           # Secrets detection patterns
|   +-- exploitation/            # Safe exploitation techniques
|   |   +-- web.md              # Web app exploitation
|   |   +-- api.md              # API attack techniques
|   |   +-- auth.md             # Auth bypass techniques
|   +-- detection/               # Detection pattern libraries
|   |   +-- patterns.py         # Python detection signatures
|   |   +-- patterns.js         # JS/TS detection signatures
|   |   +-- patterns.java       # Java detection signatures
|   +-- remediation/             # Fix templates
|       +-- python.md
|       +-- javascript.md
|       +-- general.md
+-- .gitignore
+-- LICENSE
+-- opencode.jsonc
+-- README.md                    # This file
```

---

## References

### Standards
- OWASP Top 10 — https://owasp.org/Top10/
- CWE Top 25 — https://cwe.mitre.org/top25/
- OWASP ASVS — https://owasp.org/ASVS/
- OWASP API Security Top 10 — https://owasp.org/API-Security/
- NIST SP 800-53 — https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- CVSS 3.1 — https://www.first.org/cvss/v3-1/

### Tools
- Semgrep — https://semgrep.dev/
- CodeQL — https://codeql.github.com/
- OWASP ZAP — https://www.zaproxy.org/
- Trivy — https://github.com/aquasecurity/trivy
- Nuclei — https://github.com/projectdiscovery/nuclei
- Gitleaks — https://github.com/gitleaks/gitleaks

### Training
- PortSwigger Web Security Academy — https://portswigger.net/web-security
- OWASP Web Security Testing Guide — https://owasp.org/wstg/
- Hack The Box — https://www.hackthebox.com/

---

## License

MIT — Copyright (c) 2026 Aporia
