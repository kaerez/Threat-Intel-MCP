# Security CI/CD Setup Guide

This document explains how to enable the security scanning workflows in this repository.

## Required GitHub Repository Settings

The CI/CD workflows require specific GitHub features to be enabled:

### 1. GitHub Advanced Security (Required)

Enable in: **Settings → Security → Code security and analysis**

- ✅ **Dependency graph** - Enable
- ✅ **Dependabot alerts** - Enable
- ✅ **Dependabot security updates** - Enable
- ✅ **Code scanning** - Enable
- ✅ **Secret scanning** - Enable

**Note:** GitHub Advanced Security is free for public repositories. For private repositories, it requires a GitHub Enterprise license.

### 2. Actions Permissions

Enable in: **Settings → Actions → General**

- ✅ **Allow all actions and reusable workflows**
- ✅ **Workflow permissions**: Read and write permissions
- ✅ **Allow GitHub Actions to create and approve pull requests**

### 3. Security Tab

After enabling the features above, the **Security** tab will appear with:
- Code scanning alerts (CodeQL, Semgrep)
- Secret scanning alerts (Gitleaks)
- Dependency alerts (Dependabot, Trivy)

## Workflows Overview

| Workflow | Purpose | Runs On |
|----------|---------|---------|
| `test.yml` | Tests, linting, type checking | Push to main, PRs |
| `docker-security.yml` | Container scanning, SBOM | Push to main, PRs, Daily 3 AM |
| `trivy.yml` | Dependency vulnerabilities | All branches, PRs, Daily 3 AM |
| `gitleaks.yml` | Secret detection | All branches, PRs |
| `codeql.yml` | Static analysis | Push to main, PRs, Weekly |
| `semgrep.yml` | SAST security rules | Push to main, PRs |
| `publish.yml` | Docker image publishing | Git tags (v*) |

## First-Time Setup Checklist

- [ ] Enable GitHub Advanced Security features (see above)
- [ ] Configure Actions permissions
- [ ] Verify Security tab appears in repository
- [ ] Re-run failed workflows (they will succeed after settings are enabled)
- [ ] Review security alerts in the Security tab
- [ ] (Optional) Add `CODECOV_TOKEN` secret for code coverage

## Troubleshooting

### Workflows failing with "Resource not accessible by integration"
- **Cause:** Workflow permissions not set correctly
- **Fix:** Settings → Actions → General → Set "Read and write permissions"

### CodeQL not running
- **Cause:** Code scanning not enabled
- **Fix:** Settings → Security → Enable "Code scanning"

### No Security tab visible
- **Cause:** GitHub Advanced Security features not enabled
- **Fix:** Settings → Security → Enable all features listed above

### Gitleaks failing
- **Cause:** Missing configuration file
- **Fix:** Already included in repository as `.gitleaks.toml`

## Private Repository Considerations

If this repository is private, you need:
- GitHub Enterprise license for Advanced Security features
- Or make the repository public (Advanced Security is free for public repos)

## Artifact Retention

- **Trivy scans**: 90 days (audit evidence)
- **SBOM files**: 365 days (compliance requirements)

This aligns with financial services and healthcare compliance requirements.

## Questions?

Check the workflow files in `.github/workflows/` for configuration details.
