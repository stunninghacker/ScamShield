/// Multi-stage scam detection — the attack-chain model (SPEC §6).
///
/// Scams are sequences, not single messages: bait → contact → harvest →
/// steal → cash out. [buildChain] analyzes each stage with the real rule
/// engine, keeps per-stage evidence, and rolls up to a chain verdict
/// (strongest stage wins). Pure Dart, fully tested.
library;

import '../models/verdict.dart';
import '../models/signal_match.dart';
import '../rules/scam_engine.dart';

class StageInput {
  final String title;
  final String text;
  const StageInput(this.title, this.text);
}

class StageResult {
  final String title;
  final String text;
  final List<SignalMatch> signals;
  final int score;
  final Verdict verdict;
  const StageResult({
    required this.title,
    required this.text,
    required this.signals,
    required this.score,
    required this.verdict,
  });
}

class AttackChain {
  final List<StageResult> stages;
  final int maxScore;
  final Verdict verdict;
  final int stagesFlagged;

  const AttackChain({
    required this.stages,
    required this.maxScore,
    required this.verdict,
    required this.stagesFlagged,
  });

  /// True multi-stage pattern: 2+ stages each showing scam signals.
  /// A single bad message among clean ones is NOT a chain.
  bool get isChain =>
      stagesFlagged >= 2 && verdict != Verdict.safe;
}

AttackChain buildChain(List<StageInput> inputs) {
  const engine = ScamEngine();
  final results = inputs.map((s) {
    final r = engine.analyze(s.text);
    return StageResult(
      title: s.title,
      text: s.text,
      signals: r.signals,
      score: r.score,
      verdict: r.verdict,
    );
  }).toList();

  var maxScore = 0;
  var worst = Verdict.safe;
  var flagged = 0;
  for (final r in results) {
    if (r.score > maxScore) maxScore = r.score;
    if (r.verdict.index > worst.index) worst = r.verdict;
    if (r.signals.isNotEmpty) flagged++;
  }
  return AttackChain(
      stages: results,
      maxScore: maxScore,
      verdict: worst,
      stagesFlagged: flagged);
}
