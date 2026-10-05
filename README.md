# Cybersecurity Awareness & Threat Intelligence Dashboard

A beginner-friendly, defensive security course project. It combines a local synthetic threat feed, IOC syntax validation, contextual risk and confidence, alert triage, vulnerability awareness, analyst notes, and a 30-question awareness quiz.

> **Safety and interpretation:** all 2,000 feed rows are generated locally and labeled `SYNTHETIC / DEMO ONLY`. Search is a local file lookup. The project does not resolve or contact indicators, browse URLs, scan systems, execute files, or assert confirmed incidents. A syntactically valid IOC or a high score is not proof of compromise.

## Run locally

Requires Python 3.10 or newer. From this folder:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python data\generate_threat_data.py
python backend\app.py
```

Open http://127.0.0.1:5000. The server binds to localhost by default. The bundled CSV is generated on startup if absent. SQLite stores only local quiz scores, alert triage statuses, and analyst notes. No login is implemented; keep this educational demo on localhost.

### Deploy a preview to Vercel

The project includes a Vercel Flask entry point (`app.py`) and a `public/` copy of the frontend for CDN delivery. After installing the Vercel CLI and signing in to your account, run these commands from the project root:

```powershell
npm install --global vercel
vercel
```

Choose the defaults for a new personal project to create a **preview** deployment. Flask handles the API, while static frontend files are served from `public/`. On Vercel, SQLite uses the function's temporary directory; quiz results and triage notes are ephemeral and may reset. Use a managed database before treating the app as a shared persistent service. The demo has no authentication, so use it only as an educational preview with synthetic data.

To regenerate the same dataset at any time, run the generator again (fixed seed). To use a different dataset size from Python, call `generate(count=2500, seed=10)`.

## What the project demonstrates

- **Awareness** teaches safer behavior: identify suspicious requests, protect accounts, apply updates, handle data carefully, and report early.
- **Threat intelligence (CTI)** turns threat-related observations into context that supports defensive decisions.
- **IOC:** an IP, domain, URL, file hash, or CVE-shaped identifier that may help recognize activity. Indicators can be stale, shared, or wrong; a match is a lead, not confirmation.
- **IOA:** a behavior pattern that may indicate suspicious activity. A single artifact is usually weaker evidence than a behavior sequence.
- **Vulnerability / CVE / CVSS:** a vulnerability is a weakness; a CVE is a public identifier for a disclosed vulnerability; CVSS describes severity characteristics, not whether a local asset is affected or exploited.
- **Feed:** a source of threat-related records. **Enrichment** adds context. **Correlation** finds relationships among records. Neither proves attribution.
- **Threat actor:** a conceptual person or group assessed as responsible for activity; attribution requires strong evidence and is outside this synthetic demo.
- **TTP:** tactics, techniques, and procedures describing behavior. MITRE ATT&CK is a knowledge base that organizes observed adversary tactics and techniques. This dataset uses illustrative mappings only where a behavior is present; an indicator alone does not justify a technique.
- **Threat hunting:** proactive review of authorized telemetry for signs of threats. **SOC:** a security operations center that monitors, triages, investigates, and coordinates response.

### Risk and confidence are different

Risk combines severity (30%), confidence (25%), recency (15%), observation frequency (10%), source reliability (10%), and context (10%). Confidence represents the evidence strength for an intelligence item. High potential risk with weak evidence calls for careful validation; it is not a confirmed attack. Source reliability describes a source generally and is distinct from confidence in one record. Severity labels are included in the generated data and should not be treated as incident verdicts.

### Workflow

Synthetic source → collection → normalization → syntax validation → categorization → enrichment from local fields → risk/confidence assessment → correlation → SQLite-backed triage → dashboard → awareness lessons and quiz → analyst/user.

## Architecture and folders

| Path | Purpose |
|---|---|
| `backend/app.py` | Flask API, local SQLite storage, filters and response validation |
| `backend/services.py` | IOC validation, scoring, local enrichment and correlation |
| `frontend/` | Static dashboard, styles, and browser JavaScript |
| `data/generate_threat_data.py` | Reproducible safe synthetic data generator |
| `data/threat_intelligence_dataset.csv` | 2,000 demo observations; generated locally |
| `data/vulnerabilities.csv` | Optional synthetic vulnerability export |
| `data/dashboard.sqlite3` | Runtime local state, created on first run |
| `awareness/` | Learning modules and 30 quiz questions |
| `tests/` | Unit and API tests |
| `docs/` | API guide, workflow, and presentation notes |
| `reports/`, `screenshots/` | Placeholders for student-created report and screenshots |

## API quick reference

All routes are local. The demo has no authentication; do not expose it to a network.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/threats?q=&category=&severity=` | Filter synthetic observations (max 250 returned) |
| GET | `/api/threats/{id}` | Observation detail and notes |
| POST | `/api/threats/{id}/notes` | Add a 1–1000 character local analyst note |
| GET | `/api/indicators/search?q=` | Syntax check and exact local dataset lookup |
| GET | `/api/dashboard/stats` | Summary counts and category distribution |
| GET | `/api/dashboard/trends` | Monthly synthetic record counts |
| GET | `/api/alerts` | Correlated review leads |
| PUT | `/api/alerts/{id}/status` | Set NEW, UNDER_REVIEW, MONITORING, CLOSED, FALSE_POSITIVE |
| GET | `/api/vulnerabilities` | Demo CVE-shaped entries |
| GET | `/api/awareness/modules` | Awareness lessons |
| GET | `/api/quiz` | Quiz without answer key |
| POST | `/api/quiz/submit` | Submit 30 integer answers (0-based choices) |
| GET | `/api/awareness/score` | Anonymous local quiz score history |

Validation checks syntax only. Supported indicators are IPv4/IPv6, domain, URL, MD5/SHA-1/SHA-256 format, and CVE ID. It never performs DNS, WHOIS, reputation, or HTTP lookups. The triage status API is available for API clients; the lightweight UI shows the queue read-only.

## Learning roadmap

1. Start the app and read the overview: compare observations, unique indicators, and correlated alerts.
2. Search a demo indicator by copying one from the feed. Compare local match, risk, confidence, and the caution note.
3. Filter by category or severity; open a record and add an analyst note.
4. Review synthetic CVE-shaped entries. Discuss what additional asset, patch, and exposure context a real team would need.
5. Complete the awareness lessons and quiz; see the anonymous score persist locally.
6. Explain in a class presentation why an IOC match, risk score, alert, and confirmed incident are different.

## Testing

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Tests use Flask's in-process test client and do not contact external systems.

## Limitations and next steps

The records, geographic labels, source reliability, future-dated CVE-shaped values, and ATT&CK references are illustrative; no real intelligence, asset inventory, CVSS feed, or exploitation status is asserted. Demo ATT&CK mappings are shown only alongside fictional behavior context and are not conclusions about a real event. No production authentication/RBAC or live integrations are included. A production service would need authenticated access, audit controls, expiration and provenance handling, authorized asset correlation, feed terms review, robust database migrations, secret management, and human approval before operational response. Safe extensions include STIX/TAXII ingestion of an authorized feed, CVE/KEV enrichment with provenance, and exporting a report for review.

## Interview practice: 10 questions and answers

1. **Explain your project.** I built a defensive dashboard that uses synthetic threat records to demonstrate local IOC validation, enrichment, risk and confidence scoring, correlation, a triage view, vulnerability awareness, and a security quiz. It does not claim that an indicator is a confirmed compromise.
2. **What is threat intelligence?** It is analyzed information about threats that helps defenders make decisions. Context and evidence determine how useful an indicator is.
3. **What is an IOC? Does a match prove compromise?** An IOC is an artifact such as an IP, domain, URL, hash, or CVE identifier associated with an assessment. A match is a lead; it needs authorized telemetry and context.
4. **How do risk and confidence differ?** Risk estimates potential concern from factors such as severity and context. Confidence estimates evidence strength. They are separate so uncertain but potentially serious items receive review without being presented as confirmed.
5. **What is enrichment?** Enrichment adds fields such as category, dates, source, related records, and scores to a raw indicator. This demo uses only local synthetic values.
6. **What is MITRE ATT&CK?** It is a knowledge base of adversary behaviors organized into tactics and techniques. Mapping needs behavioral context; an IP address alone is not enough.
7. **How should teams prioritize vulnerabilities?** Consider severity alongside affected assets, exposure, business impact, patch availability, and verified exploitation evidence. The synthetic entries alone cannot determine priority for a real organization.
8. **What does correlation provide?** It groups related observations to help analysts focus. Correlation does not prove shared ownership, attribution, or compromise.
9. **How might a SOC analyst use the dashboard?** Review an alert, inspect its records, validate syntax and context, document evidence, and set a triage state. Any incident determination remains a human process with authorized evidence.
10. **What are the limitations and next improvements?** Synthetic data demonstrates a workflow, not live intelligence. Next I would add a properly authorized feed, provenance and expiration, asset context, authentication, audit history, and careful validation while preserving human review.
