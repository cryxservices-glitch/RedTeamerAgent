██████╗░███████╗██████╗░████████╗███████╗░█████╗░███╗░░░███╗███████╗██████╗░
██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗░████║██╔════╝██╔══██╗
██████╔╝█████╗░░██║░░██║░░░██║░░░█████╗░░███████║██╔████╔██║█████╗░░██████╔╝
██╔══██╗██╔══╝░░██║░░██║░░░██║░░░██╔══╝░░██╔══██║██║╚██╔╝██║██╔══╝░░██╔══██╗
██║░░██║███████╗██████╔╝░░░██║░░░███████╗██║░░██║██║░╚═╝░██║███████╗██║░░██║
╚═╝░░╚═╝╚══════╝╚═════╝░░░░╚═╝░░░╚══════╝╚═╝░░╚═╝╚═╝░░░░░╚═╝╚══════╝╚═╝░░╚═╝

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/SAST-Full-6C5CE7?style=flat-square" alt="SAST"></a>
  <a href="#"><img src="https://img.shields.io/badge/DAST-Patterns-E17055?style=flat-square" alt="DAST"></a>
  <a href="#"><img src="https://img.shields.io/badge/OWASP-Top%2010-D63031?style=flat-square" alt="OWASP"></a>
  <a href="#"><img src="https://img.shields.io/badge/CWE-Top%2025-0984E3?style=flat-square" alt="CWE"></a>
  <a href="#"><img src="https://img.shields.io/badge/Secrets-Entropy%20Scan-00B894?style=flat-square" alt="Secrets"></a>
  <a href="#"><img src="https://img.shields.io/badge/Languages-12%2B-FDCB6E?style=flat-square" alt="Languages"></a>
  <a href="#"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="License"></a>
</p>

Advanced AI red-team and white-hat security agent for OpenCode. Performs deep, context-aware security analysis across 12+ languages with full OWASP Top 10, CWE Top 25, and SANS Top 25 coverage. **Detects vulnerabilities, exploits them safely to verify, and fixes them with production-ready code.**

Not a prompt wrapper — a complete security engineering framework compiled into an OpenCode agent. Contains real detection signatures, exploitation payloads, remediation templates, attack libraries, and CI/CD integration patterns.

---

- [Overview](#overview)
- [Language Support](#language-support)
- [Standards Coverage](#standards-coverage)
- [Quick Start](#quick-start)
- [Agent Usage](#agent-usage)
- [Reporting Format](#reporting-format)
- [CI/CD Integration](#cicd-integration)
- [Repository Structure](#repository-structure)
- [References](#references)
- [License](#license)

---

## Overview

### What Makes This Different

| Trait | Typical Agent | SecurityReview |
|---|---|---|
| Detection | Prompt-level rules | 350+ language-specific detection patterns with real code signatures |
| Exploitation | "Check for X" | Full payload libraries, attack chains, and safe verification procedures |
| Remediation | "Use parameterized queries" | Production-ready before/after code fixes in every supported language |
| Reporting | Text description | CVSS 3.1-scored, CWE-mapped, SARIF-compatible structured findings |
| Integration | Manual execution | Pre-commit hooks, GitHub Actions, GitLab CI with SARIF output |
| Depth | Surface scanning | Multi-phase methodology: recon → scan → verify → exploit → fix → report |
| Secrets | Basic regex | 30+ regex patterns + Shannon entropy analysis + git history scanning |
| Attack Library | None | SQLi, XSS, SSRF, path traversal, JWT, OAuth, cloud metadata payloads |

### Analysis Methodology

The agent follows a six-phase security assessment methodology:

<pre>
Phase 1 — Reconnaissance
  Stack identification, attack surface mapping, dependency analysis

Phase 2 — Automated Scanning
  SAST pattern matching, secrets detection, SCA version matching

Phase 3 — Verification
  Exploitability confirmation, attack chain mapping, bypass testing

Phase 4 — Safe Exploitation
  Payload delivery, impact demonstration, coverage confirmation

Phase 5 — Remediation
  Production-ready fix, regression test, performance review

Phase 6 — Reporting
  CVSS-scored, CWE-mapped, SARIF-compatible structured output
</pre>

### Capability Matrix

| Capability | Description |
|---|---|
| **SAST** | Deep code scanning with language-specific vulnerability signatures across 12+ stacks |
| **DAST Patterns** | Server-side exploitation templates (Nuclei, payload libraries, manual procedures) |
| **Secrets Detection** | 30+ regex patterns + Shannon entropy analysis for custom/non-standard secrets |
| **SCA** | Dependency vulnerability matching against NVD, GitHub Advisory, and OSV databases |
| **Supply Chain** | Malicious package detection, typo-squatting, dependency confusion, manifest integrity |
| **Infrastructure** | Cloud metadata attacks, container escape paths, Kubernetes RBAC audits |
| **AI/ML Security** | Prompt injection, model extraction, training data poisoning, adversarial inputs |
| **Business Logic** | Race conditions, workflow bypasses, parameter tampering, parallel session attacks |
| **Cryptography** | Weak algorithm identification, key management review, TLS configuration audit |
| **Authentication** | JWT attack surface, OAuth flow analysis, session management, MFA coverage |

---

## Language Support

| Language | Frameworks | Vulnerability Coverage |
|---|---|---|
| **Python** | Django, Flask, FastAPI | SQLi, SSTI, XSS, Command Injection, Mass Assignment, Pickle RCE, Path Traversal |
| **JavaScript/TS** | Node, React, Vue, Angular | XSS, Prototype Pollution, NoSQLi, Command Injection, eval, JWT |
| **Java** | Spring, Jakarta, Micronaut | SQLi, Path Traversal, Deserialization, XXE, Auth Bypass, Log4Shell |
| **C#/.NET** | ASP.NET MVC, WebForms, Core | SQLi, XSS, Deserialization, Path Traversal, CSRF, Insecure Config |
| **Go** | net/http, Gin, Echo, Fiber | SQLi, Command Injection, Path Traversal, TLS Misconfig, Goroutine Leaks |
| **Rust** | Actix, Axum, Rocket, Tokio | Unsafe Code, SQLi, Command Injection, Integer Overflow, Memory Safety |
| **Solidity** | Hardhat, Foundry, Truffle | Reentrancy, Arithmetic Overflows, tx.origin, Flash Loan Attacks |
| **PHP** | Laravel, Symfony, WordPress | SQLi, XSS, Deserialization, File Inclusion, Object Injection |
| **Ruby** | Rails, Sinatra, Hanami | SQLi, XSS, Mass Assignment, Command Injection, CSRF |
| **Swift** | Vapor, iOS Native | Insecure Storage, Network Layer, Authentication Bypass |
| **Kotlin** | Spring Boot, Ktor, Android | Java coverage + Coroutine Vulnerabilities, Null Safety Issues |
| **C/C++** | Native, Embedded | Buffer Overflow, Use-After-Free, Format String, Integer Wraparound |

---

## Standards Coverage

| Standard | Scope |
|---|---|
| **OWASP Top 10 (2021)** | A01–A10 — full detection signatures, exploitation procedures, and fix patterns per class |
| **CWE Top 25 (2024)** | All 25 weaknesses — CVSS-scored, language-mapped, with framework-specific detection |
| **SANS Top 25** | Complete mapping with code-level detection examples |
| **OWASP ASVS Level 2** | V1–V14 architecture and verification requirements coverage |
| **OWASP API Security Top 10** | BOLA, broken auth, excessive data exposure, mass assignment, rate limiting |
| **OWASP Mobile Top 10** | Insecure data storage, untrusted inputs, side-channel data leakage |
| **NIST SP 800-53** | Mapped security control families (AC, AU, IA, SC, SI) |
| **PCI DSS v4.0** | Payment data security requirements (requirement 6, 7, 8, 10) |
| **CVSS 3.1** | Every finding scored with full vector string and severity breakdown |

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/cryxservices-glitch/SecurityReviewAgent.git

# Run a full audit
@SecurityReview audit this codebase for vulnerabilities

# Scan a specific file
@SecurityReview find vulnerabilities in src/api/users.py

# Get a fix for a specific vulnerability class
@SecurityReview how to fix SQL injection in this Go handler

# Run a secrets scan
@SecurityReview scan for secrets in the entire repository
```

---

## Agent Usage

### Installation

**Per-project**: The `.opencode/agents/` directory is pre-configured. OpenCode auto-detects agents in the project's `.opencode/agents/` folder.

**Global**: Copy the agent to your global OpenCode configuration:
```bash
cp .opencode/agents/SecurityReview.md ~/.config/opencode/agents/
```

### Commands

| Command | Description |
|---|---|
| `@SecurityReview audit <path>` | Full security audit of a codebase or directory |
| `@SecurityReview scan <file>` | Scan a specific file for vulnerabilities |
| `@SecurityReview test <type> <path>` | Test for a specific vulnerability class (sqli, xss, ssrf, etc.) |
| `@SecurityReview fix <finding-id>` | Generate a production-ready fix for a previous finding |
| `@SecurityReview exploit <type>` | Show exploitation payloads and verification steps for a vulnerability class |
| `@SecurityReview report` | Generate a structured security report for the current session |
| `@SecurityReview deps <path>` | Dependency vulnerability scan against known CVEs |
| `@SecurityReview secrets <path>` | Deep secrets scan (regex + entropy + git history) |

### Depth Levels

| Depth | Loop Count | Use Case |
|---|---|---|
| **Quick** | 1 | Fast surface scan, dependency check, configuration review |
| **Standard** | 4–8 | Full SAST + secrets + SCA analysis (default) |
| **Deep** | 16–32 | Full analysis with exploitation verification and attack chain mapping |
| **Competitive** | 32–64 | Red-team style multi-vector attack simulation with full reporting |

---

## Reporting Format

Every finding follows a structured standard compatible with SARIF for GitHub Code Scanning integration:

<pre>
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
│ User input from the 'id' query parameter is directly     │
│ concatenated into a SQL query without parameterization.  │
├─────────────────────────────────────────────────────────┤
│ Vulnerable Code:                                         │
│   user = db.query(f"SELECT * FROM users WHERE id =      │
│                   {request.args.get('id')}")             │
├─────────────────────────────────────────────────────────┤
│ Exploitation:                                            │
│   GET /api/user?id=1 UNION SELECT * FROM credentials    │
│   Confirmed via boolean-based blind and time-based delay │
├─────────────────────────────────────────────────────────┤
│ Remediation:                                             │
│   user = db.query("SELECT * FROM users WHERE id = ?",   │
│                   [request.args.get('id')])              │
└─────────────────────────────────────────────────────────┘
</pre>

Each finding includes:
- **Title**: CWE-prefixed, human-readable identifier
- **Severity**: CVSS 3.1 score with vector string
- **Location**: File path and line number
- **Description**: Impact and exploitability summary
- **Vulnerable Code**: Exact code snippet with the flaw
- **Exploitation**: Verification steps and payloads used
- **Remediation**: Production-ready code fix
- **Regression Test**: Test case to prevent re-introduction

---

## CI/CD Integration

### Pre-Commit Hook

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
        args: ["--format", "sarif", "--output", "security-report.sarif"]
```

### GitHub Actions

```yaml
# .github/workflows/security-review.yml
name: Security Review
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  analyze:
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
      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-report.sarif
          category: security-review
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security-review:
  stage: test
  script:
    - opencode run agent SecurityReview --scan-dir . --format gl-sast --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
  only:
    - main
    - merge_requests
```

---

## Repository Structure

```
SecurityReviewAgent/
+-- .opencode/
|   +-- agents/
|       +-- SecurityReview.md       # OpenCode agent — full security engine
+-- security-review/                # Knowledge base framework
|   +-- vulnerabilities/
|   |   +-- owasp-top10.md          # OWASP Top 10 deep reference
|   |   +-- cwe-top25.md            # CWE Top 25 detection signatures
|   |   +-- secrets.md              # Secrets detection pattern library
|   +-- exploitation/
|   |   +-- web.md                  # Web application exploitation techniques
|   |   +-- api.md                  # API security exploitation techniques
|   +-- detection/
|       +-- patterns.py             # Python detection pattern signatures
+-- opencode.jsonc                   # OpenCode configuration
+-- LICENSE
+-- README.md                        # This file
```

---

## References

### Standards & Frameworks

| Standard | Link |
|---|---|
| OWASP Top 10 (2021) | [owasp.org/Top10](https://owasp.org/Top10/) |
| CWE Top 25 (2024) | [cwe.mitre.org/top25](https://cwe.mitre.org/top25/) |
| OWASP ASVS | [owasp.org/ASVS](https://owasp.org/ASVS/) |
| OWASP API Security Top 10 | [owasp.org/API-Security](https://owasp.org/API-Security/) |
| NIST SP 800-53 | [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) |
| CVSS 3.1 | [first.org/cvss](https://www.first.org/cvss/v3-1/) |
| OWASP Testing Guide | [owasp.org/wstg](https://owasp.org/wstg/) |

### Open Source Tools

| Tool | Purpose | Link |
|---|---|---|
| **Semgrep** | SAST rule engine | [semgrep.dev](https://semgrep.dev/) |
| **CodeQL** | Semantic code analysis | [codeql.github.com](https://codeql.github.com/) |
| **OWASP ZAP** | DAST / web app scanning | [zaproxy.org](https://www.zaproxy.org/) |
| **Trivy** | Container and dependency scanning | [github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy) |
| **Nuclei** | Vulnerability template scanner | [github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |
| **Gitleaks** | Secrets scanning | [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |
| **TruffleHog** | Deep secrets discovery | [github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |

### Training & Certification

| Resource | Link |
|---|---|
| PortSwigger Web Security Academy | [portswigger.net/web-security](https://portswigger.net/web-security) |
| OWASP Web Security Testing Guide | [owasp.org/wstg](https://owasp.org/wstg/) |
| Hack The Box | [hackthebox.com](https://www.hackthebox.com/) |
| PentesterLab | [pentesterlab.com](https://pentesterlab.com/) |

---

## License

MIT — Copyright (c) 2026 Aporia

*"Every vulnerability is a fix waiting to be written."*
