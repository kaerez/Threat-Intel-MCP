# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report security vulnerabilities by emailing:

**security@ansvar.systems**

Or use GitHub's private vulnerability reporting:
1. Go to the repository's **Security** tab
2. Click **Report a vulnerability**
3. Fill out the form with details

### What to Include

Please include the following in your report:

- **Description**: Clear description of the vulnerability
- **Impact**: What an attacker could achieve
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Affected Versions**: Which versions are affected
- **Suggested Fix**: If you have one (optional)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 90 days

### Disclosure Policy

- We follow [coordinated disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)
- We will credit reporters in release notes (unless anonymity is requested)
- We ask that you do not publicly disclose until a fix is available

## Security Measures

This project implements several security measures:

### Code Security
- **CodeQL**: Automated static analysis on every PR
- **Semgrep**: SAST scanning for common vulnerabilities
- **Trivy**: Dependency vulnerability scanning
- **pip-audit**: Python package security auditing

### Supply Chain Security
- **Gitleaks**: Secret detection in commits
- **Socket Security**: Dependency risk analysis
- **OSSF Scorecard**: Supply chain security assessment
- **Dependabot**: Automated dependency updates

### Container Security
- **Trivy**: Container image scanning
- **Non-root containers**: Services run as non-root users
- **Minimal base images**: Alpine-based where possible

### Runtime Security
- **Input validation**: All API inputs are validated via Pydantic schemas
- **SQL injection prevention**: Parameterized queries via SQLAlchemy ORM
- **Internal-only deployment**: Designed for private network use, not public internet
- **No secrets in code**: Environment variables for all credentials

## Security Best Practices for Users

1. **Never commit `.env` files** - Use environment variables
2. **Use strong database passwords** - Change default credentials
3. **Enable TLS** - Use HTTPS in production
4. **Regular updates** - Keep dependencies updated
5. **Network isolation** - Run in private networks when possible
6. **API key rotation** - Rotate NVD/OpenAI keys periodically

## Known Security Considerations

### Data Sources
This server fetches data from external sources:
- NVD (NIST) - US government vulnerability database
- MITRE ATT&CK - Threat intelligence framework
- MITRE ATLAS - AI/ML attack techniques
- MITRE CAPEC - Common attack patterns
- MITRE CWE - Software weaknesses
- MITRE D3FEND - Defensive techniques
- CISA KEV - Known exploited vulnerabilities
- FIRST EPSS - Exploit prediction scores
- AWS/Azure/GCP - Cloud security properties

These are trusted sources, but network requests should be validated.

### Local Database
CVE and threat intelligence data is stored locally. Ensure:
- Database is not exposed to public networks
- Regular backups are maintained
- Access is restricted to authorized users
