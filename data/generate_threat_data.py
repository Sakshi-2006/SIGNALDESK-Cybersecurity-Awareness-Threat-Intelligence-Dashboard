"""Generate a deterministic, harmless synthetic threat-intelligence CSV."""
import csv, hashlib, random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from services import calculate_threat_risk
OUT = ROOT / "data" / "threat_intelligence_dataset.csv"
CATEGORIES = ["PHISHING", "MALWARE", "RANSOMWARE", "CREDENTIAL THREATS", "WEB THREATS", "NETWORK THREATS", "VULNERABILITY EXPOSURE", "SOCIAL ENGINEERING", "DATA EXPOSURE", "ACCOUNT SECURITY"]
TYPES = ["IP ADDRESS", "DOMAIN", "URL", "FILE HASH", "EMAIL/SENDER DOMAIN", "CVE ID"]
SOURCES = [("Internal SOC", "A"), ("Security Vendor", "A"), ("Public Threat Feed", "B"), ("Research Report", "B"), ("Community Submission", "C"), ("Unknown Source", "D")]
SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]
BEHAVIORS = {"PHISHING": ("Synthetic credential-harvesting message theme", "Initial Access", "T1566"), "CREDENTIAL THREATS": ("Synthetic repeated login-guessing observation", "Credential Access", "T1110"), "NETWORK THREATS": ("Synthetic application-layer command channel pattern", "Command and Control", "T1071"), "RANSOMWARE": ("Synthetic data-encryption-for-impact scenario", "Impact", "T1486")}

def make_value(rng, kind, i):
    if kind == "IP ADDRESS": return f"192.0.2.{i % 254 + 1}"
    if kind in ("DOMAIN", "EMAIL/SENDER DOMAIN"): return f"demo-{i}.example.com"
    if kind == "URL": return f"https://demo-{i}.example.invalid/sample"
    if kind == "FILE HASH": return hashlib.sha256(f"synthetic-demo-{i}".encode()).hexdigest()
    return f"CVE-2099-{100000 + i}"

def generate(count=2000, seed=20261005, path=OUT):
    rng = random.Random(seed); now = datetime.now(timezone.utc)
    fields = ["threat_id", "timestamp", "threat_name", "threat_category", "indicator_type", "indicator_value", "source_name", "source_reliability", "confidence_score", "severity", "risk_score", "status", "first_seen", "last_seen", "country_or_region_optional", "description", "behavior_context_optional", "mitre_tactic_optional", "mitre_technique_optional", "cve_id_optional", "record_label"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields); writer.writeheader()
        for i in range(count):
            kind = TYPES[i % len(TYPES)]; cat = CATEGORIES[i % len(CATEGORIES)]; source, rel = rng.choice(SOURCES)
            seen = now - timedelta(days=rng.randrange(0, 365)); last = seen + timedelta(hours=rng.randrange(0, 240))
            sev = rng.choices(SEVERITIES, [5, 18, 35, 30, 12])[0]; conf = rng.randint(25, 98)
            sev_base = dict(zip(SEVERITIES, [10, 25, 50, 75, 95]))[sev]
            days_old = (now - seen).days
            recency = max(0, 100 - round(days_old / 365 * 100))
            risk = calculate_threat_risk(sev, conf, recency, 1, {"A": 92, "B": 78, "C": 58, "D": 35}[rel], rng.randint(20, 85))
            behavior, tactic, technique = BEHAVIORS.get(cat, ("", "", ""))
            value = make_value(rng, kind, i)
            description = "Synthetic training record; not a report of a real threat or incident."
            if behavior: description += " Illustrative behavior context is fictional and supports only a demo ATT&CK mapping."
            writer.writerow(dict(threat_id=f"SYN-{i+1:05d}", timestamp=seen.isoformat(), threat_name=f"Demo {cat.title()} Observation {i+1:04d}", threat_category=cat, indicator_type=kind, indicator_value=value, source_name=source, source_reliability=rel, confidence_score=conf, severity=sev, risk_score=risk, status=rng.choice(STATUSES), first_seen=seen.isoformat(), last_seen=last.isoformat(), country_or_region_optional="DEMO ONLY", description=description, behavior_context_optional=behavior, mitre_tactic_optional=tactic, mitre_technique_optional=technique, cve_id_optional=value if kind == "CVE ID" else "", record_label="SYNTHETIC / DEMO ONLY"))
    return path

if __name__ == "__main__": print(f"Wrote {generate()}")
