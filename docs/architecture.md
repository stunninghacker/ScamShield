# ScamShield — Architecture

Honest technical map of what ships in this repository. Every claim here is
verifiable against the file it names; tests enforce the critical ones.

## One pipeline, many inputs

All inputs funnel through a single entry point:

```
paste · share-intent · OCR photo · URL · QR payload · radar transcript
        └──────────────► ScanPipeline.analyze()  (lib/analysis/scan_pipeline.dart)
```

`ScanPipeline.analyze` is the only path that produces a verdict, and it is
side-effect bounded: it runs the engine, builds the attack chain, asks the
AI layer for an explanation, and logs exactly one indicator-only event.
Failure is explicit: if anything throws, the result is
`verdict=suspicious, category='Scan failed', error=<exception>` — a crash
never masquerades as a SAFE verdict.

Callers may pass `verdictFloor` (QR tab does). A floor can only **raise**
the engine's verdict (and the score is lifted to that tier's threshold so
score and verdict always agree). No caller can lower a verdict.

## Layer 1 — deterministic engine (owns every verdict)

- `lib/rules/signals.dart` — 10 detectors, each returning matched spans
  with weights: `LINK_RISK`, `SECRET_REQUEST`, `URGENCY_THREAT`,
  `REWARD_LURE`, `PAYMENT_PULL`, `CALLBACK`, `REMOTE_ACCESS`, `JOB_LURE`,
  `DIGITAL_ARREST`, `IMPERSONATION`. Shared guards: advisory negation
  ("never share your OTP" is advice, not a request), completed-change
  notifications, URL masking, phone-vs-amount disambiguation.
- `lib/rules/constants.dart` — documented weight tiers:
  critical classes (secret / remote / arrest / payment) = 60,
  technique classes (urgency / reward / job) = 40,
  supporting (impersonation 20, callback 15), link base 20 capped at 60.
  Thresholds: `suspicious ≥ 30`, `dangerous ≥ 60`.
- `lib/rules/scam_engine.dart` — sum of per-class contributions (each class
  counted once, capped), then two documented sanity rules:
  1. *suspicious floor* — signals present but score < 30 ⇒ suspicious;
  2. *demand gate* — score is clamped below `dangerous` unless the message
     contains an actual demand (credential, remote access, arrest
     coercion, money) or urgency combined with a link/lure. A pile of weak
     cues can never reach the red verdict on its own.

The engine is regex/rule based, offline, and deterministic: the same text
always yields the same verdict, score and spans.

## Layer 2 — context

- `lib/analysis/verdict_report.dart` — category label, calibrated
  confidence, AI-context tags from fired signals.
- `lib/analysis/attack_chain.dart` — `familyFor()` maps the *combination*
  of fired signals plus message evidence to one of 9 families (phishing,
  bankingFraud, digitalArrest, jobScam, remoteAccess, deliveryScam,
  investmentScam, accountTakeover, none). Precedence is the spec: arrest >
  job-vs-invest > remote > … > residual phishing. `buildSignalChain()`
  orders fired signals into the attack story shown in Why/Timeline.
- `lib/analysis/url_intel.dart`, `lib/analysis/qr_intel.dart` — local
  parsing only. URLs are never fetched or resolved; QR payloads are
  classified, never executed.

## Layer 3 — explanation (never the verdict)

- `lib/llm/ai_provider.dart` — `LocalGemmaProvider` (if a user-bundled
  `.task` exists) → `RuleFallbackProvider` (always available).
- `lib/llm/gemma_service.dart` — `init()` returns `false` instead of
  throwing when the model file is absent; `explain()` reports
  `llmUsed:false` in that case.
- `lib/llm/prompt_template.dart` + sanitizer — the prompt embeds only
  fired signals and the engine verdict; output claims about unfired
  signals are dropped. The AI layer cannot flip a verdict.

The Gemma model file is **not** in this repository (`assets/models/`
contains only `.gitkeep`); tests assert that.

## Storage & privacy

- `lib/events/threat_events.dart` — indicator-only events in
  `shared_preferences`: category, risk, score, signal ids, evidence count,
  action, family, chain id, digit-masked preview. Full message text is
  never persisted. Export/Import is clipboard JSON, user-initiated, capped
  (256 KB / 100 events) and schema-validated.
- `android/app/src/main/AndroidManifest.xml` — **no INTERNET permission**,
  no `allowBackup`. The app cannot open a network socket even if code
  tried.
- `test/privacy_audit_test.dart` reads the manifest, pubspec, every file
  under `lib/` and `assets/models/` on every run and fails if any of the
  above regresses (no placeholders).

## UI map

| Screen | File | Shows |
| --- | --- | --- |
| Home | `lib/ui/home_screen.dart` | paste scan, feature grid, recent events |
| Result / Why | `lib/ui/result_screen.dart`, `why_screen.dart` | spans, weights, family, actions |
| ScamLens | `lib/ui/lens_screen.dart` | QR (engine + structural floor), URL, photo OCR |
| Radar | `lib/ui/radar_screen.dart` | simulated call stream (labeled scripts, no mic) |
| Timeline | `lib/ui/timeline_screen.dart` | multi-stage KYC chain |
| Command Center | `lib/ui/command_screen.dart` | local event feed + clipboard sync |
| Judge Mode | `lib/ui/judge_screen.dart` | live status read from code, nothing staged |
| Privacy Center | `lib/ui/privacy_screen.dart` | processing disclosure |

## How correctness is measured

- `test/eval_harness_test.dart` — 289 hand-labeled cases checked against
  the **documented verdict rubric** (header states the rubric and the
  metric definitions). Measures rubric consistency; its 100% is labeled as
  such in `audit/eval_report.json`.
- `test/heldout_eval_test.dart` — 55 templates written from the rubric
  *before* the engine ran. First pass (unedited) and current results are
  both committed: `audit/heldout_report_first_pass.json`,
  `audit/heldout_report.json`. Misses are printed, not hidden.
- Pinned contracts: `test/rules_test.dart`, `test/attack_chain_test.dart`,
  `test/intel_test.dart` freeze the engine behaviours that must not drift.

## Known limitations (stated, not hidden)

- No URL reputation/age/redirect data offline — those fields report
  "unavailable" instead of guessing.
- A bare legitimate URL is a *cue*, so it can be labeled suspicious
  (warn, never block). This is the one known held-out miss, kept in the
  report on purpose.
- Voice input is simulated transcripts (no live call interception —
  platform restriction).
- Sync is manual clipboard JSON, not automatic wireless.
