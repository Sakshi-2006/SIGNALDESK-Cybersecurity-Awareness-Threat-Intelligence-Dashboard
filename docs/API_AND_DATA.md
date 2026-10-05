# Data model and API notes

## Record model

The CSV row identifies a synthetic observation (`threat_id`, timestamp and descriptive name), categorizes it, stores one indicator and its source, records source reliability separately from item confidence, carries severity and computed risk, and includes workflow status, first/last seen, notes, optional ATT&CK tactic/technique, and optional CVE-shaped identifier. Every row has an explicit synthetic label. The SQLite database holds only mutable local user interaction: quiz score history, alert status, and analyst notes. It does not duplicate the CSV dataset.

## Object distinctions

| Object | Meaning in this demo |
|---|---|
| Observation | One synthetic row in the feed |
| Indicator | A value extracted from an observation |
| Alert | A correlation rule's prompt for review |
| Threat | A possible source or condition assessed from evidence |
| Incident | A confirmed or formally declared security event; none are claimed here |

## Risk model

`risk = 0.30 × severity + 0.25 × confidence + 0.15 × recency + 0.10 × frequency + 0.10 × source reliability + 0.10 × context`, rounded to 0–100. The service provides the explicit scoring function for experimentation; generated demonstration rows use a randomized but bounded score for variety. Risk is prioritization, not a diagnosis. Confidence is the supplied evidence score, while reliability is a general source rating. They must not be collapsed into one field.

## API behavior

- JSON responses; unsupported inputs return 400, missing records return 404.
- Search is a local exact-value lookup after syntax validation. It does not perform network access.
- `GET /api/threats` filters `q`, `category`, and `severity`, and caps response rows at 250 while returning the total.
- Quiz answers are numeric choice indexes; answer keys are never returned by `GET /api/quiz`.
- SQLite interaction state has no user identity and is for a single local learner.
- The service intentionally has no authentication. Run on localhost only.
