/// Central scan pipeline: the ONE path every input (paste, share, OCR
/// photo, URL, QR-text, radar transcript) funnels through.
///
/// text → ScamEngine (verdict+spans+breakdown, timed) → category/confidence
/// → Gemma-or-fallback explanation → ThreatEvent logged (indicators only).
/// Never throws: on total failure returns a safe empty result.
library;

import 'package:flutter/foundation.dart';
import '../analysis/verdict_report.dart';
import '../events/threat_events.dart';
import '../llm/gemma_service.dart';
import '../llm/prompt_template.dart';
import '../models/verdict.dart';
import '../models/signal_match.dart';
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
  final String explanation;
  final String whatToDo;
  final bool llmUsed;
  final int latencyMs;
  final String eventId;

  const PipelineResult({
    required this.sourceText,
    required this.source,
    required this.signals,
    required this.breakdown,
    required this.score,
    required this.verdict,
    required this.category,
    required this.confidence,
    required this.explanation,
    required this.whatToDo,
    required this.llmUsed,
    required this.latencyMs,
    required this.eventId,
  });
}

class ScanPipeline {
  static final ScanPipeline instance = ScanPipeline._();
  ScanPipeline._();
  static const _engine = ScamEngine();

  int lastLatencyMs = 0;

  Future<PipelineResult> analyze(
    String rawText, {
    String source = 'text',
    bool demo = false,
  }) async {
    final text = rawText.trim();
    try {
      final sw = Stopwatch()..start();
      final out = _engine.analyze(text);
      sw.stop();
      lastLatencyMs = sw.elapsedMilliseconds;

      final category = categoryFor(out.signals);
      final confidence =
          confidenceFor(out.score, hasSignals: out.signals.isNotEmpty);
      final explained = await GemmaService.instance.explain(
        message: text,
        signals: out.signals,
        verdict: out.verdict,
        score: out.score,
      );
      final event = EventLog.fromScan(
        source: source,
        category: category,
        risk: out.verdict.name,
        score: out.score,
        confidence: confidence,
        signals: out.signals,
        fullText: text,
        demo: demo,
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
        score: out.score,
        verdict: out.verdict,
        category: category,
        confidence: confidence,
        explanation: explained.explanation,
        whatToDo: explained.whatToDo,
        llmUsed: explained.llmUsed,
        latencyMs: lastLatencyMs,
        eventId: event.id,
      );
    } catch (e) {
      debugPrint('[Pipeline] failed: $e');
      final fb =
          PromptTemplate.fallback(signals: const [], verdict: Verdict.safe);
      return PipelineResult(
        sourceText: text,
        source: source,
        signals: const [],
        breakdown: const {},
        score: 0,
        verdict: Verdict.safe,
        category: 'Genuine',
        confidence: 0.0,
        explanation: fb.explanation,
        whatToDo: fb.whatToDo,
        llmUsed: false,
        latencyMs: 0,
        eventId: '',
      );
    }
  }
}
