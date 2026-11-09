# Security Policy

The Bouclier project takes the security of our application, our users, and the systems scanned by our tool seriously. This document outlines our security policies, supported versions, and responsible vulnerability disclosure process.

---

## 1. Supported Versions

Security updates and critical vulnerability patches are actively provided for the following releases:

| Version | Supported | Notes |
|---|---|---|
| `1.0.x` | :white_check_mark: | Current active release branch |
| `< 1.0.0` | :x: | Pre-release development versions (unsupported) |

We strongly encourage all users and organizations deploying Bouclier to keep their installations updated to the latest patch release of the `1.0.x` series.

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability or potential threat in Bouclier, **please do not disclose it publicly** through public GitHub issues, discussions, or social media until it has been reviewed and addressed.

### Responsible Disclosure Method
We use **GitHub Private Vulnerability Reporting** to handle security disclosures safely and confidentially.

To submit a private vulnerability report:
1. Navigate to the repository's Security tab:  
   **[Submit a Vulnerability Report](https://github.com/1steve78/Bouclier/security/advisories/new)**
2. Provide a descriptive title and detailed summary of the vulnerability.
3. Include clear, step-by-step reproduction instructions or a minimal Proof of Concept (PoC).
4. Outline the potential impact (e.g., SSRF bypass, denial of service, memory exhaustion, credential leakage).

If you are unable to use GitHub Private Vulnerability Reporting, open a minimal issue with the title `[Security Advisory Request]` asking the maintainers to initiate a private advisory discussion without disclosing vulnerability details in the issue body.

---

## 3. Vulnerability Response Timeline

Upon receiving a private security disclosure, the maintainers will:
- **Acknowledge:** Confirm receipt of your report within 48 business hours.
- **Assess & Validate:** Evaluate the severity, reproducibility, and scope within 5 business days.
- **Remediate:** Develop, test, and package a fix in a private branch or advisory fork.
- **Coordinated Release:** Publish a patch release (e.g., `v1.0.1`) along with a public GitHub Security Advisory (GHSA) crediting the reporter (unless anonymity is requested).

---

## 4. Scope & Security Guarantees

### In Scope
- Server-Side Request Forgery (SSRF) bypasses or DNS rebinding vulnerabilities in the scanning engine, HTTP client, or threat feed synchronizer.
- Memory or resource exhaustion vulnerabilities (denial of service via unbounded body reads or malformed inputs).
- Exposure or persistence of sensitive feed credentials or secrets in SQLite, CLI outputs, or logs.
- Privilege escalation or command execution via the TUI, CLI, MCP server, or REST API.
- Tampering or forgery of stored scan records or threat intelligence bundles without invalidating cryptographic checksums.

### Out of Scope
- Denial of Service attacks requiring physical access to the local machine or direct tampering with local files (`~/.bouclier/bouclier.db`).
- Attacks against external third-party services, threat feed providers, or targets scanned by Bouclier.
- Vulnerabilities in upstream Go runtime or operating system kernel components.
- Scans initiated against user-specified targets operating as intended (Bouclier connects to the remote target's public port 80/443 to inspect certificates and headers; this is the fundamental function of the tool).
