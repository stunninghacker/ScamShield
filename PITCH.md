# ScamShield — Pitch

## Problem
India loses ₹1,000s of crores yearly to KYC/OTP phishing, lottery lures, and
fake courier/payment messages. Victims are often non-technical parents who get
a scary "account BLOCKED in 24 hours" SMS with a lookalike link — and obey.

## Why on-device matters
- **Privacy:** SMS content is the most sensitive data on a phone. Cloud
  scanning = uploading it. ScamShield never lets text leave the device
  (airplane-mode demo proves it).
- **Latency & cost:** verdict in milliseconds, no server bill, works in
  low-connectivity India.
- **Hackathon fit:** the theme is "AI, preferably on-device" — Gemma + ML Kit
  run fully offline, no API key, no quota.

## Hybrid rule + LLM design (why it wins)
- **Rules OWN the verdict** (deterministic, instant, testable). 7 India-tuned
  signals with exact highlighted spans — the demo can't misfire.
- **Gemma ONLY explains** (plain language a parent understands), grounded to
  fired signals with a sanitizer + fallback. It can never invent threats or
  flip the verdict — including the crucial restraint moment: a genuine bank
  alert returns green SAFE.
- Provenance UI: every highlighted word traces to a rule hit. Judges SEE why.

## Competitive gap
- **Truecaller / Google spam filter:** cloud blocklists — binary spam/not-spam,
  no reasoning, privacy cost, miss zero-day lookalike domains.
- **ChatGPT wrappers:** online, slow, hallucinate verdicts, leak SMS content.
- **ScamShield:** offline, explainable, grounded, private. No competitor does
  on-device verdict + on-device explanation + span-level provenance.
