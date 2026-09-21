/// AI provider architecture — honest local-model status (SPEC §5).
///
/// The .task file is large and license-gated, so it cannot be bundled
/// blindly. Instead of faking "AI running locally", the app routes every
/// explanation through an [AiProvider] and Judge Mode reports which one is
/// active:
///
///   AI STATUS
///   Local Gemma   AVAILABLE / UNAVAILABLE
///   Fallback      ACTIVE / INACTIVE
library;

import 'package:flutter/foundation.dart';
import '../models/signal_match.dart';
import '../models/verdict.dart';
import 'gemma_service.dart';
import 'prompt_template.dart';

/// Structured explanation output, whoever produces it.
class AiExplanation {
  final String explanation;
  final String whatToDo;
  final bool fromLocalModel;
  const AiExplanation({
    required this.explanation,
    required this.whatToDo,
    required this.fromLocalModel,
  });
}

abstract class AiProvider {
  /// Human name shown in Judge Mode, e.g. "Local Gemma (gemma-3-1b-it)".
  String get name;

  /// True when this provider can actually generate right now.
  Future<bool> get available;

  Future<AiExplanation> explain({
    required String message,
    required List<SignalMatch> signals,
    required Verdict verdict,
    required int score,
    List<String> context = const [],
  });
}

/// On-device Gemma via flutter_gemma. Available only after the user places
/// the .task file in assets/models/ and init succeeds.
class LocalGemmaProvider implements AiProvider {
  @override
  String get name => 'Local Gemma (gemma-3-1b-it)';

  @override
  Future<bool> get available async {
    if (GemmaService.instance.isReady) return true;
    try {
      return await GemmaService.instance.init();
    } catch (_) {
      return false;
    }
  }

  @override
  Future<AiExplanation> explain({
    required String message,
    required List<SignalMatch> signals,
    required Verdict verdict,
    required int score,
    List<String> context = const [],
  }) async {
    final r = await GemmaService.instance.explain(
      message: message,
      signals: signals,
      verdict: verdict,
      score: score,
      context: context,
    );
    return AiExplanation(
      explanation: r.explanation,
      whatToDo: r.whatToDo,
      fromLocalModel: r.llmUsed,
    );
  }
}

/// Deterministic grounded fallback — always available, never hallucinates.
/// This is what judges see until the model file is bundled; verdicts are
/// identical either way because the rule engine owns them.
class RuleFallbackProvider implements AiProvider {
  @override
  String get name => 'Rule fallback (built-in explainer)';

  @override
  Future<bool> get available async => true;

  @override
  Future<AiExplanation> explain({
    required String message,
    required List<SignalMatch> signals,
    required Verdict verdict,
    required int score,
    List<String> context = const [],
  }) async {
    final fb =
        PromptTemplate.fallback(signals: signals, verdict: verdict);
    debugPrint(
        '[AI] fallback active (local model unavailable) — verdict untouched.');
    return AiExplanation(
      explanation: fb.explanation,
      whatToDo: fb.whatToDo,
      fromLocalModel: false,
    );
  }
}

/// Routes to Local Gemma when available, else the rule fallback.
/// Call [status] for the Judge Mode status board.
class AiRouter {
  static final AiRouter instance = AiRouter._();
  AiRouter._();

  final LocalGemmaProvider local = LocalGemmaProvider();
  final RuleFallbackProvider fallback = RuleFallbackProvider();

  bool lastUsedLocal = false;

  Future<AiExplanation> explain({
    required String message,
    required List<SignalMatch> signals,
    required Verdict verdict,
    required int score,
    List<String> context = const [],
  }) async {
    if (await local.available) {
      final r = await local.explain(
          message: message,
          signals: signals,
          verdict: verdict,
          score: score,
          context: context);
      lastUsedLocal = r.fromLocalModel;
      if (r.fromLocalModel) return r;
      // Model present but inference failed mid-call → honest fallback.
    }
    lastUsedLocal = false;
    return fallback.explain(
        message: message,
        signals: signals,
        verdict: verdict,
        score: score,
        context: context);
  }

  /// Snapshot for Judge Mode. Never claims local AI when it isn't running.
  Future<({bool gemmaAvailable, bool fallbackActive})>
      status() async {
    final g = await local.available;
    return (
      gemmaAvailable: g,
      fallbackActive: !g || !lastUsedLocal,
    );
  }
}
