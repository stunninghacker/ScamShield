/// Central scan pipeline: the ONE path every input (paste, share, OCR
/// photo, URL, QR-text, radar transcript) funnels through.
///
/// text → ScamEngine (verdict+spans+breakdown, timed) → category/confidence
/// → Gemma-or-fallback explanation → ThreatEvent logged (indicators only).
/// Never throws: on total failure it returns an EXPLICIT failure result
/// (suspicious + "scan could not run" copy, [PipelineResult.error] set) —
/// a crash must never masquerade as a SAFE verdict.
library;

import 'package:flutter/foundation.dart';
import '../analysis/attack_chain.dart';
import '../analysis/verdict_report.dart';
import '../events/threat_events.dart';
import '../llm/ai_provider.dart';
import '../models/verdict.dart';
import '../models/signal_match.dart';
import '../rules/constants.dart';
import '../rules/scam_engine.dart';

class PipelineResult {
  final String sourceText;
  final String source; // text | url | qr | image | voice
  final List<SignalMatch> signals;
  final Map<String, int> breakdown;
  final int score;
  final Verdict verdict;
  final String category;
  final double confidence;
  final List<String> context;
  final String explanation;
  final String whatToDo;
  final bool llmUsed;
  final int latencyMs;
  final int aiMs;
  final String eventId;
  final ScamFamily family; // evidence-first family from signal combinations
  final SignalChain chain; // ordered attack story for this message
  /// Non-null only when the pipeline itself failed (never a rule verdict):
  /// callers must show "scan could not run", not "safe".
  final String? error;

  PipelineResult({
    required this.sourceText,
    required this.source,
    required this.signals,
    required this.breakdown,
    required this.score,
    required this.verdict,
    required this.category,
    required this.confidence,
    required this.context,
    required this.explanation,
    required this.whatToDo,
    required this.llmUsed,
    required this.latencyMs,
    required this.aiMs,
    required this.eventId,
    required this.family,
    required this.chain,
    this.error,
  });
}

class ScanPipeline {
  static final ScanPipeline instance = ScanPipeline._();
  ScanPipeline._();
  static const _engine = ScamEngine();

  static int _rank(Verdict v) {
    switch (v) {
      case Verdict.safe:
        return 0;
      case Verdict.suspicious:
        return 1;
      case Verdict.dangerous:
        return 2;
    }
  }

  /// Structural cues (QR payee, URL lookalike tier) may only RAISE the
  /// verdict, never lower it, and the score is lifted to that tier's
  /// threshold so score and verdict always agree.
  static int _raise(int score, Verdict floor) =>
      score < _floorScore(floor) ? _floorScore(floor) : score;

  static int _floorScore(Verdict floor) =>
      floor == Verdict.dangerous
          ? RuleThresholds.dangerous
          : RuleThresholds.suspicious;

  int lastLatencyMs = 0;
  int lastAiMs = 0;

  Future<PipelineResult> analyze(
    String rawText, {
    String source = 'text',
    bool demo = false,
    Verdict? verdictFloor,
  }) async {
    final text = rawText.trim();
    try {
      final sw = Stopwatch()..start();
      final out = _engine.analyze(text);
      sw.stop();
      lastLatencyMs = sw.elapsedMilliseconds;

      // Engine owns the verdict; a caller-supplied structural floor (QR
      // payee, URL risk tier) can only escalate it.
      var verdict = out.verdict;
      var score = out.score;
      if (verdictFloor != null && _rank(verdictFloor) > _rank(verdict)) {
        verdict = verdictFloor;
        score = _raise(score, verdictFloor);
      }

      final category = categoryFor(out.signals);
      final confidence =
          confidenceFor(out.score, hasSignals: out.signals.isNotEmpty);
      final context = contextTagsFor(out.signals);
      final aiSw = Stopwatch()..start();
      final explained = await AiRouter.instance.explain(
        message: text,
        signals: out.signals,
        verdict: verdict,
        score: score,
        context: context,
      );
      aiSw.stop();
      lastAiMs = aiSw.elapsedMilliseconds;
      // Evidence-first chain: engine output → ordered story + family.
      // Verdict/score/category untouched — the engine still owns them.
      final chain = buildSignalChain(
        signals: out.signals,
        breakdown: out.breakdown,
        verdict: verdict,
        score: score,
        text: text,
      );
      final event = EventLog.fromScan(
        source: source,
        category: category,
        risk: verdict.name,
        score: score,
        confidence: confidence,
        signals: out.signals,
        fullText: text,
        demo: demo,
        family: chain.family.label,
      );
      try {
        await EventLog().log(event);
      } catch (e) {
        debugPrint('[Pipeline] event log failed: $e');
      }
      return PipelineResult(
        sourceText: text,
        source: source,
        signals: out.signals,
        breakdown: out.breakdown,
        score: score,
        verdict: verdict,
        category: category,
        confidence: confidence,
        context: context,
        explanation: explained.explanation,
        whatToDo: explained.whatToDo,
        llmUsed: explained.fromLocalModel,
        latencyMs: lastLatencyMs,
        aiMs: lastAiMs,
        eventId: event.id,
        family: chain.family,
        chain: chain,
      );
    } catch (e) {
      debugPrint('[Pipeline] failed: $e');
      // Honest failure: the engine did not run, so we cannot claim SAFE.
      // Amber "unverified" beats a false green light.
      return PipelineResult(
        sourceText: text,
        source: source,
        signals: const [],
        breakdown: const {},
        score: 0,
        verdict: Verdict.suspicious,
        category: 'Scan failed',
        confidence: 0.0,
        context: const [],
        explanation:
            'This message could not be scanned — the analysis did not run. '
            'ScamShield does not know whether it is safe, so treat it as '
            'unverified: do not open links or share codes.',
        whatToDo:
            'Scan again. If it keeps failing, assume the message may be '
            'hostile and check with the official app or phone number.',
        llmUsed: false,
        latencyMs: 0,
        aiMs: 0,
        eventId: '',
        family: ScamFamily.none,
        chain: SignalChain(
            family: ScamFamily.none,
            verdict: Verdict.suspicious,
            score: 0,
            steps: const []),
        error: e.toString(),
      );
    }
  }
}
