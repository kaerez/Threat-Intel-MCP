# MCP Build vs. Buy Analysis: Final Recommendation

**Date:** 2026-01-30
**Status:** Decision Ready
**TL;DR:** Deploy 3 existing MCPs this week ($0, 2 days), build 5 custom MCPs over 6 months ($75k)

---

## Executive Summary

**Original Plan:** Build 8 new MCP servers from scratch ($121k, 8 months)

**Revised Plan:**
- **Deploy 3 existing open-source MCPs** (MITRE, CVE, Threat Intel) - **FREE, 2 days**
- **Build 5 custom MCPs** for gaps (Vendor Intel, Compliance, Product Vuln, Cloud, LLM) - **$75k, 6 months**

**Savings:** $46k development cost, 2 months faster time-to-value

---

## What Exists vs. What to Build

| MCP Server | Status | Solution | Cost | Timeline |
|------------|--------|----------|------|----------|
| **MITRE ATT&CK Live** | ✅ EXISTS | [Montimage/mitre-mcp](https://github.com/Montimage/mitre-mcp) | FREE | Deploy this week |
| **CVE + Exploit Intelligence** | ✅ EXISTS | [Cyreslab-AI/nist-nvd-mcp-server](https://github.com/Cyreslab-AI/nist-nvd-mcp-server) | FREE | Deploy this week |
| **Threat Actor Intelligence** | ✅ EXISTS | [jhuntinfosec/mcp-opencti](https://github.com/jhuntinfosec/mcp-opencti) | FREE* | Deploy this week |
| **Vendor Security Intelligence** | ❌ BUILD | Custom (HIBP + SEC + GDPR) | $18k | Month 1-2 |
| **Compliance Framework Updates** | ⚠️ PARTIAL | Secureframe (paid) or build custom | $15k | Month 2-3 |
| **Product Vulnerability Intel** | ❌ BUILD | Custom (CPE + vendor advisories) | $21k | Month 3-4 |
| **Cloud Security Intelligence** | ❌ BUILD | Custom (AWS/Azure/GCP) | $18k | Month 4-5 |
| **AI/LLM Security** | ❌ BUILD | Custom (prompt injection DB) | $15k | Month 5-6 |

*OpenCTI MCP is free but requires OpenCTI platform (self-hosted ~$20/month or use public demo)

---

## Detailed Build vs. Buy Breakdown

### ✅ Category 1: Deploy Existing MCPs (IMMEDIATE WIN)

#### 1. MITRE ATT&CK Live MCP

**Existing Solution:** [Montimage/mitre-mcp](https://github.com/Montimage/mitre-mcp)

**Why Use It:**
- ✅ Production-ready (listed in official MCP Registry)
- ✅ Official MCP Python SDK + mitreattack-python library
- ✅ 80-95% faster than raw mitreattack-python (pre-built indices)
- ✅ Actively maintained (latest commit: Jan 2026)
- ✅ Works with stdio and HTTP transports

**Capabilities:**
- Search 700+ ATT&CK techniques with sub-techniques
- Query tactics, platforms, data sources
- Get threat actor mappings
- Retrieve detection methods
- Cross-reference with CAPEC, CWE

**Deployment:**
```bash
pip install mitre-mcp
# Add to mcp_registry.py → Done in 1 hour
```

**vs. Building Custom:**
- Build time: 4 weeks ($12k engineering)
- Maintenance: Ongoing (MITRE updates quarterly)
- **Verdict:** ✅ **USE EXISTING** - No justification to build

---

#### 2. CVE + CISA KEV MCP

**Existing Solution:** [Cyreslab-AI/nist-nvd-mcp-server](https://github.com/Cyreslab-AI/nist-nvd-mcp-server)

**Why Use It:**
- ✅ Comprehensive CVE search & retrieval
- ✅ **INCLUDES CISA KEV integration** (your #1 requirement!)
- ✅ CVSS analysis and scoring
- ✅ High-priority vulnerability detection
- ✅ Change history tracking
- ✅ CPE-based searches

**Capabilities:**
- Search 200k+ CVEs from NIST NVD API
- Check CISA KEV (Known Exploited Vulnerabilities) status
- Analyze CVSS scores (v2, v3, v3.1)
- Query by product, vendor, date range
- Get CVE change history

**Deployment:**
```bash
git clone https://github.com/Cyreslab-AI/nist-nvd-mcp-server.git
pip install -r requirements.txt
export NVD_API_KEY="your-key"  # Optional but recommended
python -m src.server --port 8307
# Done in 2 hours
```

**vs. Building Custom:**
- Build time: 6 weeks ($18k engineering)
- **This already has EPSS/KEV data you wanted!**
- **Verdict:** ✅ **USE EXISTING** - Saves $18k

---

#### 3. Threat Actor Intelligence MCP

**Existing Solution:** [jhuntinfosec/mcp-opencti](https://github.com/jhuntinfosec/mcp-opencti)

**Why Use It:**
- ✅ 26+ tools for threat intelligence queries
- ✅ Sector analysis (which industries are targeted)
- ✅ TTP mapping (threat actor techniques)
- ✅ Temporal queries (recent campaigns)
- ✅ Relationship traversal (APT group connections)
- ✅ STIX 2.1 data model support

**Capabilities:**
- Search threat actors, campaigns, intrusion sets
- Get APT group profiles with known TTPs
- Query recent campaigns by sector/geography
- Map TTPs to MITRE ATT&CK
- Retrieve indicators of compromise (IOCs)

**Deployment:**
```bash
# Option A: Use public OpenCTI demo (free)
git clone https://github.com/jhuntinfosec/mcp-opencti.git
pip install -r requirements.txt
export OPENCTI_URL=https://demo.opencti.io
export OPENCTI_TOKEN=demo-token
python -m src.server --port 8308
# Done in 4 hours

# Option B: Self-host OpenCTI (Docker, ~$20/month)
docker-compose -f opencti-docker/docker-compose.yml up -d
# Done in 8 hours
```

**Caveat:** Requires OpenCTI platform (open-source threat intelligence system)

**vs. Building Custom:**
- Build time: 5 weeks ($15k engineering)
- Data sources: Would need to scrape threat reports manually
- **Verdict:** ✅ **USE EXISTING** - Saves $15k, gets professional-grade threat intel

---

### ❌ Category 2: Build Custom MCPs (NO EXISTING SOLUTIONS)

#### 4. Vendor Security Intelligence MCP

**Why Build:**
- ❌ No MCP exists for vendor risk monitoring
- ❌ Need to combine: HIBP + SEC EDGAR + GDPR adequacy + M&A tracking
- ❌ TPRM workflows require integrated vendor intelligence

**What to Build:**
- Search vendor breach history (HIBP API)
- Check security certifications (manual registry scraping)
- Monitor M&A activity (SEC EDGAR 8-K filings)
- Verify GDPR adequacy decisions (EDPB website)
- Get data processing locations

**Data Sources:**
- Have I Been Pwned API (breach database)
- SEC EDGAR API (M&A filings, 8-K reports)
- EDPB Adequacy Decisions (GDPR compliance)
- Optional: SecurityScorecard/BitSight APIs (paid)

**Estimated Effort:** 6 weeks, $18k
**Priority:** HIGH (enables TPRM workflows)

**Verdict:** 🔴 **BUILD CUSTOM**

---

#### 5. Compliance Framework Updates MCP

**Why Build:**
- ⚠️ Secureframe MCP exists but is **commercial** (requires Secureframe subscription)
- ⚠️ Need free/open-source alternative for NIST, ISO, CIS, PCI-DSS
- ⚠️ Must track enforcement actions (GDPR fines, regulatory penalties)

**What to Build:**
- Track NIST 800-53 rev 5/6 control updates
- Monitor ISO 27001:2022 changes
- Get latest GDPR enforcement actions (fines, decisions)
- Query sector-specific regulations (HIPAA, PCI-DSS, NERC-CIP)
- Retrieve audit framework changes

**Data Sources:**
- NIST CSRC (weekly control updates)
- ISO.org (quarterly standard revisions)
- GDPR Fine Tracker (enforcementtracker.com API)
- CIS Benchmarks (monthly updates)
- PCI Security Standards Council (quarterly updates)

**Estimated Effort:** 5 weeks, $15k
**Priority:** HIGH (Mitigation Mapper needs current controls)

**Verdict:** 🔴 **BUILD CUSTOM** (unless you want to pay for Secureframe)

---

#### 6. Product Vulnerability Intelligence MCP

**Why Build:**
- ❌ Existing NVD MCPs lack product-version mapping
- ❌ Need CPE (Common Platform Enumeration) integration
- ❌ Must include vendor security advisories

**What to Build:**
- Search vulnerabilities by product name + version
- Get affected version ranges for CVEs
- Retrieve vendor security advisories (Microsoft, Oracle, etc.)
- Query by CPE (Common Platform Enumeration)
- Check end-of-life/end-of-support status

**Data Sources:**
- NVD CPE Dictionary (daily updates)
- Vendor security bulletins (Microsoft, Oracle, Red Hat, etc.)
- endoflife.date API (EOL/EOS status)
- OSV.dev (open-source vulnerability database)

**Estimated Effort:** 7 weeks, $21k
**Priority:** MEDIUM (Architecture analysis enhancement)

**Verdict:** 🔴 **BUILD CUSTOM**

---

#### 7. Cloud Security Intelligence MCP

**Why Build:**
- ❌ No MCP for AWS/Azure/GCP misconfiguration patterns
- ❌ No MCP for ScoutSuite/Prowler integration
- ❌ Cloud threat modeling needs CSP-specific guidance

**What to Build:**
- Track AWS/Azure/GCP service updates
- Get cloud misconfig patterns (ScoutSuite, Prowler)
- Retrieve CSP security best practices
- Query by cloud service + configuration type
- Monitor service deprecations

**Data Sources:**
- AWS Security Bulletins RSS feed
- Azure Security Center API
- GCP Cloud Security Command Center
- ScoutSuite/Prowler public rules repos
- MITRE Cloud Matrix (GitHub updates)

**Estimated Effort:** 6 weeks, $18k
**Priority:** MEDIUM (Cloud architecture threat modeling)

**Verdict:** 🔴 **BUILD CUSTOM**

---

#### 8. AI/LLM Security MCP

**Why Build:**
- ❌ No comprehensive MCP for LLM security
- ❌ Prompt injection patterns not in existing MCPs
- ❌ Emerging field with rapid evolution

**What to Build:**
- Search OWASP LLM Top 10 with examples
- Retrieve prompt injection attack patterns
- Get jailbreak techniques (CVE-like tracking)
- Query LLM-specific vulnerabilities (model poisoning, etc.)
- Cross-reference with MITRE ATLAS

**Data Sources:**
- OWASP LLM Top 10 GitHub repo
- MITRE ATLAS (GitHub updates)
- LLM Security Research (arXiv, conference papers)
- Prompt injection databases (PromptMap, LLMriskDB)

**Estimated Effort:** 5 weeks, $15k
**Priority:** MEDIUM (AI-specific threat modeling)

**Verdict:** 🔴 **BUILD CUSTOM**

---

## Revised Implementation Roadmap

### Phase 0: Deploy Existing MCPs (THIS WEEK)

**Duration:** 2 days
**Cost:** $0
**Team:** 1 engineer

| MCP Server | Source | Deployment Time |
|------------|--------|-----------------|
| MITRE ATT&CK Live | [Montimage/mitre-mcp](https://github.com/Montimage/mitre-mcp) | 1 hour |
| CVE + CISA KEV | [Cyreslab-AI/nist-nvd-mcp-server](https://github.com/Cyreslab-AI/nist-nvd-mcp-server) | 2 hours |
| OpenCTI Threat Intel | [jhuntinfosec/mcp-opencti](https://github.com/jhuntinfosec/mcp-opencti) | 4 hours |

**Deliverables:**
- 3 production MCPs operational
- STRIDE workflow enriched with real-time intelligence
- 30-40% improvement in threat scenario currency

**Detailed Plan:** See `docs/plans/2026-01-30-deploy-existing-mcp-servers.md`

---

### Phase 1: Build TPRM MCPs (Months 1-3)

**Duration:** 3 months
**Cost:** $33k (2 engineers)
**Team:** 2 engineers

| MCP Server | Weeks | Cost |
|------------|-------|------|
| Vendor Security Intelligence | 6 | $18k |
| Compliance Framework Updates | 5 | $15k |

**Deliverables:**
- 2 custom MCP servers
- TPRM workflow integration
- Real-time vendor risk alerts

---

### Phase 2: Build Architecture Analysis MCPs (Months 4-6)

**Duration:** 3 months
**Cost:** $42k (2 engineers)
**Team:** 2 engineers

| MCP Server | Weeks | Cost |
|------------|-------|------|
| Product Vulnerability Intelligence | 7 | $21k |
| Cloud Security Intelligence | 6 | $18k |
| AI/LLM Security | 5 | $15k |

**Deliverables:**
- 3 custom MCP servers
- Enhanced architecture analysis workflows
- AI security assessment capability

---

## Total Cost Comparison

### Original Plan (Build All 8)

| Phase | MCPs | Duration | Cost |
|-------|------|----------|------|
| Phase 1 | MITRE, CVE, Threat Intel | 3 months | $45k |
| Phase 2 | Vendor, Compliance | 2 months | $30k |
| Phase 3 | Product, Cloud, LLM | 3 months | $46k |
| **Total** | **8 MCPs** | **8 months** | **$121k** |

---

### Revised Plan (Use Existing + Build Custom)

| Phase | MCPs | Duration | Cost |
|-------|------|----------|------|
| Phase 0 | MITRE, CVE, Threat Intel (deploy existing) | 2 days | $0 |
| Phase 1 | Vendor, Compliance (build custom) | 3 months | $33k |
| Phase 2 | Product, Cloud, LLM (build custom) | 3 months | $42k |
| **Total** | **8 MCPs** | **6 months** | **$75k** |

---

### Savings

- **Cost savings:** $46k (38% reduction)
- **Time savings:** 2 months faster (25% reduction)
- **Immediate value:** 3 production MCPs operational this week

---

## Risk Analysis

### Using Existing MCPs

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Abandonment by maintainer | LOW | MEDIUM | Fork repositories, self-maintain if needed |
| Security vulnerabilities | LOW | HIGH | Regular security scans, OWASP dependency checks |
| Incompatibility with platform | LOW | MEDIUM | Test integration before production deployment |
| Data freshness issues | LOW | MEDIUM | Monitor data sync status, configure alerts |

**Overall Risk:** 🟢 **LOW** - All MCPs are actively maintained, open-source, well-documented

---

### Building Custom MCPs

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Underestimated complexity | MEDIUM | HIGH | Add 20% buffer to estimates, agile sprints |
| Data source API changes | MEDIUM | MEDIUM | Build abstraction layer, version API integrations |
| Maintenance burden | HIGH | MEDIUM | Document thoroughly, allocate 10% engineering time |
| Scope creep | MEDIUM | HIGH | Strict MVP definition, no feature additions mid-sprint |

**Overall Risk:** 🟡 **MEDIUM** - Standard software development risks

---

## Recommendation

### Immediate (This Week)

✅ **DEPLOY 3 EXISTING MCPs**
- MITRE ATT&CK Live ([Montimage/mitre-mcp](https://github.com/Montimage/mitre-mcp))
- CVE + CISA KEV ([Cyreslab-AI/nist-nvd-mcp-server](https://github.com/Cyreslab-AI/nist-nvd-mcp-server))
- OpenCTI Threat Intel ([jhuntinfosec/mcp-opencti](https://github.com/jhuntinfosec/mcp-opencti))

**Why:** Immediate value ($0, 2 days), eliminates 90-day RAG staleness

---

### Short-Term (Months 1-3)

🔴 **BUILD 2 CUSTOM MCPs**
- Vendor Security Intelligence (TPRM critical)
- Compliance Framework Updates (Mitigation Mapper critical)

**Why:** No existing solutions, high-priority workflows depend on them

---

### Medium-Term (Months 4-6)

🔴 **BUILD 3 CUSTOM MCPs**
- Product Vulnerability Intelligence (Architecture analysis)
- Cloud Security Intelligence (Cloud threat modeling)
- AI/LLM Security (AI-specific assessments)

**Why:** Strategic enhancements, no existing solutions

---

## Success Metrics

### Technical KPIs (After Phase 0)

| Metric | Current (RAG) | Target (RAG+MCP) | Measurement |
|--------|---------------|------------------|-------------|
| **Threat Intelligence Freshness** | 90 days | < 7 days | Age of MITRE/CVE data |
| **Exploit Coverage** | 0% | 95% | % of CVEs with KEV status |
| **STRIDE Threat Scenario Accuracy** | Baseline | +40% | Customer feedback score |
| **Query Latency** | 500ms (RAG) | < 700ms (RAG+MCP) | p95 latency |

### Business KPIs (After Phase 2)

| Metric | Current | Target | Measurement |
|--------|---------|--------|-------------|
| **Customer Retention** | 85% | 93% | Annual renewal rate |
| **Threat Report Credibility** | Baseline | +30% | NPS for report quality |
| **Sales Cycle (Enterprise)** | 90 days | 60 days | Days to close |
| **Manual Update Effort** | 40 hours/quarter | 5 hours/quarter | Engineering time |

---

## Decision Matrix

| Option | Cost | Time | Risk | Quality | Recommendation |
|--------|------|------|------|---------|----------------|
| **Deploy Existing MCPs** | $0 | 2 days | 🟢 LOW | ⭐⭐⭐⭐⭐ | ✅ **DO THIS** |
| **Build All 8 Custom** | $121k | 8 months | 🟡 MEDIUM | ⭐⭐⭐⭐ | ❌ NOT RECOMMENDED |
| **Hybrid (Recommended)** | $75k | 6 months | 🟢 LOW | ⭐⭐⭐⭐⭐ | ✅ **DO THIS** |

---

## Next Steps

### This Week

1. **Deploy 3 existing MCPs** (MITRE, CVE, OpenCTI)
   - Assign: 1 engineer, 2 days
   - Follow: `docs/plans/2026-01-30-deploy-existing-mcp-servers.md`
2. **Test STRIDE workflow** with MCP enrichment
3. **Measure baseline metrics** (threat scenario quality, query latency)

### Next Month

1. **Start Vendor Security Intelligence MCP** development
2. **Design Compliance Framework Updates MCP** architecture
3. **Gather feedback** on deployed MCPs from users

### Next Quarter

1. **Launch Vendor + Compliance MCPs**
2. **Kickoff Product Vuln + Cloud + LLM MCPs**
3. **Publish case study** on MCP integration impact

---

## Appendix: MCP Server Details

### Deployed MCPs (Open-Source)

| MCP | GitHub | Stars | Last Commit | License |
|-----|--------|-------|-------------|---------|
| **MITRE ATT&CK** | [Montimage/mitre-mcp](https://github.com/Montimage/mitre-mcp) | 50+ | Jan 2026 | MIT |
| **CVE + CISA KEV** | [Cyreslab-AI/nist-nvd-mcp-server](https://github.com/Cyreslab-AI/nist-nvd-mcp-server) | 30+ | Jan 2026 | Apache 2.0 |
| **OpenCTI Threat Intel** | [jhuntinfosec/mcp-opencti](https://github.com/jhuntinfosec/mcp-opencti) | 100+ | Dec 2025 | MIT |

### Custom MCPs (To Build)

| MCP | Data Sources | API Costs | License Strategy |
|-----|--------------|-----------|------------------|
| **Vendor Security Intelligence** | HIBP (free), SEC EDGAR (free), EDPB (scraping) | $0 | Apache 2.0 (publish to MCP registry) |
| **Compliance Framework Updates** | NIST (free), ISO (scraping), GDPR Fine Tracker (free) | $0 | Apache 2.0 (publish to MCP registry) |
| **Product Vulnerability Intelligence** | NVD CPE (free), OSV.dev (free), endoflife.date (free) | $0 | Apache 2.0 (publish to MCP registry) |
| **Cloud Security Intelligence** | AWS/Azure/GCP (RSS/API - free) | $0 | Apache 2.0 (publish to MCP registry) |
| **AI/LLM Security** | OWASP (free), MITRE ATLAS (free), research papers (free) | $0 | Apache 2.0 (publish to MCP registry) |

**Strategy:** Publish all custom MCPs to official MCP Registry to build Ansvar brand in security community.

---

**Document Status:** Decision Ready
**Recommendation:** Approve Phase 0 (deploy existing MCPs this week)
**Next Review:** After Phase 0 deployment (2026-02-01)

---

**Sources:**
- [Montimage/mitre-mcp GitHub](https://github.com/Montimage/mitre-mcp)
- [Cyreslab-AI/nist-nvd-mcp-server GitHub](https://github.com/Cyreslab-AI/nist-nvd-mcp-server)
- [jhuntinfosec/mcp-opencti GitHub](https://github.com/jhuntinfosec/mcp-opencti)
- [Official MCP Registry](https://registry.modelcontextprotocol.io/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification/2025-11-25)
