# ScamShield — Offline on-device scam/phishing shield

> Share or screenshot an SMS/WhatsApp message → flags scam, explains WHY in plain
> language, highlights the exact suspicious text. **Everything runs offline.
> Nothing leaves your phone.** ✈️-mode ready.

## Architecture (the winning decision)

Two layers, strict boundary:

1. **RULE ENGINE (pure Dart, `lib/rules/`) — OWNS THE VERDICT.**
   Pattern matching only. Every fired signal returns id + label + weight +
   exact matched substring + char offsets. Weighted sum → verdict:
   `SAFE (<30, green)` / `SUSPICIOUS (30–59, amber)` / `DANGEROUS (≥60, red)`.
   Instant, deterministic, demo can't misfire.
2. **ON-DEVICE LLM (Gemma via `flutter_gemma`, `lib/llm/`) — ONLY EXPLAINS.**
   Input: message + fired signals. Output: ≤90-word plain-language explanation
   + one "what to do" line. Hard rule: may only explain fired signals, never
   invent reasons, never change verdict. Zero signals → calm "looks genuine"
   note. All outputs sanitized; any failure → deterministic fallback
   (demo never crashes).

```
share text/image → (ML Kit OCR if image) → ScamEngine.analyze()
  → verdict+spans → GemmaService.explain() → Result screen (highlighted spans)
```

No network calls anywhere. No analytics. No backend. History in
`shared_preferences` only.

## Project layout

```
lib/
  main.dart
  models/signal_match.dart  — id/label/weight/matchedText/start/end
  models/scan_result.dart   — sourceText/signals/score/verdict/explanation
  rules/constants.dart      — ALL weights + thresholds (tune here only)
  rules/signals.dart        — 7 detectors, pure functions + offsets
  rules/scam_engine.dart    — pipeline: detect → cap links → sum → verdict
  data/demo_samples.dart    — 4 hard-coded demo messages
  llm/prompt_template.dart  — EXACT grounded prompt + fallback
  llm/gemma_service.dart    — flutter_gemma wrapper + sanitizer
  ocr/ocr_service.dart      — ML Kit offline text recognition
  share/share_handler.dart  — receive_sharing_intent (text + images)
  history/history_store.dart— local history
  ui/home_screen.dart       — paste box + Scan + 4 demo buttons + 🔒Offline
  ui/result_screen.dart     — verdict banner + highlighted msg + explanation
  ui/history_screen.dart    — local history
  ui/widgets/highlighted_text.dart — provenance highlighting
test/rules_test.dart        — unit tests for EVERY signal + demo verdicts
assets/models/.gitkeep      — put your .task model here (gitignored)
android/                    — minSdk 26, share-intent filters, NO internet perm
```

## Setup

### 0. Prereqs
- Flutter latest stable, Android SDK 34, JDK 17. This machine already has
  Android SDK + JDK 21 (works; 17 recommended).
- A Gemma `.task` model file (see below).

### 1. Install Flutter (this machine doesn't have it yet)
```powershell
choco install flutter -y
# then:
flutter doctor
```

### 2. Get packages
```powershell
cd C:\Users\saksh\OneDrive\Desktop\Scam_Shield
flutter pub get
```

### 3. Where to place the Gemma model file
1. Download **once on a networked machine** (never at runtime):
   - `gemma-3-1b-it.task` (recommended, smallest) or `gemma-2b-it.task`
   - from Kaggle / HuggingFace Gemma`.task` (MediaPipe LLM Inference format).
2. Copy it to **both**:
   - `assets/models/gemma-3-1b-it.task`  (bundled at build time — `pubspec.yaml` already includes `assets/models/`)
   - It is auto-copied to app storage on first launch (`ensureModelFile`).
3. If the file is missing, the app still works: verdict + highlighting come
   from the rule engine, explanation uses the built-in grounded fallback
   (badge shows "built-in explainer"). Place the file to unlock Gemma text.

> `assets/models/*.task` is gitignored (large). Ship the APK with the model
> inside for the hackathon demo device.

### 4. (If `android/` looks incomplete) regenerate platform shell
```powershell
flutter create . --org com.scamshield.app --project-name scamshield
flutter pub get
```

### 5. Run tests (rule engine — graded)
```powershell
flutter test
```
All tests in `test/rules_test.dart` must pass: each signal, demo verdicts
(1→DANGEROUS, 2→DANGEROUS, 3→SUSPICIOUS, 4→SAFE), exact offsets, grounding.

### 6. Build the APK (single command)
```powershell
flutter build apk --debug
# output: build/app/outputs/flutter-apk/app-debug.apk
```

## 6-line demo script (3 minutes, airplane mode ON)

1. **Airplane mode ON.** Open ScamShield — point at the "🔒 Offline" badge: "nothing leaves your phone."
2. Tap **Demo 1 (KYC phishing)** → red "Likely a scam", link + "OTP" highlighted → read Gemma's 2-line why.
3. Tap **Demo 4 (genuine alert)** → green "Looks genuine" — "this restraint is why you can trust it."
4. **Share path:** open SMS/WhatsApp → Share a scam screenshot → ScamShield → OCR → verdict live.
5. **Paste path:** paste any forwarded SMS → Scan → amber/red + "What to do".
6. Close: "Rules decide, Gemma explains, ML Kit reads, all offline — no blocklist, no cloud."

## Airplane-mode guarantee (self-check)
- `grep -r "http\.\|dio\|analytics\|firebase\|telemetry" lib/` → only scam-pattern
  strings + comments; zero network imports (`dart:io` is only for local files).
- `AndroidManifest.xml` has **no** `INTERNET` permission.
- Models (Gemma `.task` + ML Kit) bundled/provisioned on-device; no runtime download.

## Tuning
Edit only `lib/rules/constants.dart` (`RuleWeights`, `RuleThresholds`), then
`flutter test` to confirm the 4 demos still land DANGEROUS/DANGEROUS/SUSPICIOUS/SAFE.

## Stretch (only after core is solid)
- Live SMS ingestion (`READ_SMS` + permission rationale) — off by default.
- Hindi explanation (same model, prompt flag).
- Link visualizer (real vs lookalike domain side-by-side).
