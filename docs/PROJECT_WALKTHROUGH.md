# Beginner walkthrough

## Workflow

The generator creates a repeatable set of harmless documentation-range addresses, reserved example domains, `.invalid` URLs, synthetic hashes, and clearly marked CVE-shaped strings. Flask reads the CSV locally. The validator tests string shape; the enrichment function compares a normalized value with local records. Category/type grouping makes a review alert when several higher-risk observations share labels. The dashboard explains every alert as a lead. Notes, alert status, and awareness results are stored in SQLite.

## Defensive concepts

**Technical intelligence** includes indicators and vulnerability context. **Tactical intelligence** describes behavior and defensive patterns. **Strategic intelligence** supports longer-term leadership decisions; **operational intelligence** concerns campaigns and activity over time. This course demo focuses on technical and awareness-oriented concepts and uses only illustrative tactical mapping.

Typical defensive controls include MFA, unique passwords, managed updates, email reporting, endpoint protection, backups, least privilege, network monitoring, and incident response plans. Awareness is a complement to technical controls, not a substitute.

## Roles this demonstrates

SOC and cybersecurity analysts triage. CTI analysts assess provenance, confidence, context, and behavior. Incident responders document and contain verified events. Security and vulnerability engineers prioritize fixes. Awareness specialists build learning material. Threat hunters investigate authorized telemetry. The demo shows basic workflows; it does not replace production tooling or operational experience.

## Useful walkthrough for a presentation

1. Point out the synthetic-data banner and `confirmed incidents: 0`.
2. Explain a record's risk and confidence as distinct values.
3. Search one indicator and show the local-only warning.
4. Demonstrate that a valid syntax result says nothing about maliciousness.
5. Open an observation, add a note, and explain evidence/disposition.
6. Review awareness content and a quiz score.

## Safe future work

Use authorized, licensed feeds with provenance, expiration, and a clearly visible source label. Add authentication and role checks before any shared deployment. Enrich CVEs with source-linked severity and affected asset data only where authorized. Require analyst approval for consequential actions. Keep logs minimal and avoid personal data in quiz results.
