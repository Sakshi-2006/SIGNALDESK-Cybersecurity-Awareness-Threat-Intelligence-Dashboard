"""Defensive, local-only validation, scoring, enrichment and correlation."""
import ipaddress, re
from urllib.parse import urlsplit

SOURCE_RELIABILITY = {"Internal SOC": 95, "Security Vendor": 90, "Public Threat Feed": 75, "Research Report": 80, "Community Submission": 60, "Unknown Source": 35}
SEVERITY_BASE = {"INFORMATIONAL": 10, "LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 95}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
HASH_PATTERNS = {"MD5": re.compile(r"^[a-fA-F0-9]{32}$"), "SHA-1": re.compile(r"^[a-fA-F0-9]{40}$"), "SHA-256": re.compile(r"^[a-fA-F0-9]{64}$")}

def validate_indicator(value):
    """Check syntax only. Never resolves, fetches, or contacts the value."""
    raw = str(value or "").strip()
    if not raw: return {"valid": False, "indicator_type": "UNKNOWN", "normalized_value": "", "validation_notes": "Enter a value."}
    try:
        ip = ipaddress.ip_address(raw)
        return {"valid": True, "indicator_type": "IP ADDRESS", "normalized_value": ip.compressed, "validation_notes": "Syntactically valid IP; this does not establish maliciousness."}
    except ValueError: pass
    if CVE_RE.fullmatch(raw): return {"valid": True, "indicator_type": "CVE ID", "normalized_value": raw.upper(), "validation_notes": "CVE identifier syntax only; no live lookup performed."}
    for name, pattern in HASH_PATTERNS.items():
        if pattern.fullmatch(raw): return {"valid": True, "indicator_type": "FILE HASH", "normalized_value": raw.lower(), "validation_notes": f"Syntactically valid {name} hash; file not accessed."}
    candidate = raw.split("@", 1)[-1] if "@" in raw else raw
    if "://" in candidate:
        try:
            u = urlsplit(candidate)
            if u.scheme.lower() in ("http", "https") and u.hostname and "." in u.hostname:
                return {"valid": True, "indicator_type": "URL", "normalized_value": candidate, "validation_notes": "URL syntax only; the URL was not opened or checked."}
        except ValueError: pass
    if re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", candidate):
        kind = "EMAIL/SENDER DOMAIN" if "@" in raw else "DOMAIN"
        return {"valid": True, "indicator_type": kind, "normalized_value": candidate.lower(), "validation_notes": "Domain syntax only; DNS was not queried."}
    return {"valid": False, "indicator_type": "UNKNOWN", "normalized_value": raw, "validation_notes": "Value does not match supported IP, domain, URL, hash, or CVE syntax."}

def calculate_threat_risk(severity, confidence, recency=70, observations=1, source_reliability=60, context=50):
    freq = min(100, 30 + max(0, observations-1)*12)
    return round(.30*SEVERITY_BASE.get(str(severity).upper(), 10) + .25*confidence + .15*recency + .10*freq + .10*source_reliability + .10*context)

def score_confidence(record):
    return int(record.get("confidence_score", 0))

def enrich_indicator(value, records):
    validation = validate_indicator(value)
    if not validation["valid"]: return {"validation": validation, "known_in_demo_dataset": False, "matches": []}
    matches = [r for r in records if r["indicator_value"].lower() == validation["normalized_value"].lower()]
    if not matches: return {"validation": validation, "known_in_demo_dataset": False, "matches": [], "note": "No local synthetic record matched. No external lookup was attempted."}
    categories = {r["threat_category"] for r in matches}
    related = [r for r in records if r["threat_category"] in categories and r["indicator_value"].lower() != validation["normalized_value"].lower()][:10]
    return {"validation": validation, "known_in_demo_dataset": True, "matches": matches, "risk_score": max(int(r["risk_score"]) for r in matches), "confidence_score": max(score_confidence(r) for r in matches), "related_categories": sorted(categories), "related_alerts": [r["threat_id"] for r in matches if int(r["risk_score"]) >= 61], "related_indicators": [r["indicator_value"] for r in related], "analyst_note": "Dataset match is an observation for review, not proof of compromise."}

def correlate(records):
    """Group shared synthetic category/type signals into reviewable alerts."""
    groups = {}
    for r in records:
        if int(r["risk_score"]) >= 61:
            key = (r["threat_category"], r["indicator_type"])
            groups.setdefault(key, []).append(r)
    result = []
    for (cat, kind), rows in groups.items():
        if len(rows) >= 3:
            result.append({"alert_id": f"ALT-{len(result)+1:03d}", "kind": kind, "title": f"{cat.title()} observations ({len(rows)})", "severity": max((r["severity"] for r in rows), key=lambda x: SEVERITY_BASE[x]), "count": len(rows), "status": "NEW", "reason": "Synthetic observations share a category and indicator type; correlation is a lead for analyst review.", "actions": ["Validate scope and evidence", "Check authorized internal telemetry", "Record disposition"]})
    return result
