import 'signal_match.dart';

/// Verdict owned SOLELY by the rule engine. The LLM never changes this.
enum Verdict { safe, suspicious, dangerous }

extension VerdictX on Verdict {
  String get label {
    switch (this) {
      case Verdict.safe:
        return 'Looks genuine';
      case Verdict.suspicious:
        return 'Looks suspicious';
      case Verdict.dangerous:
        return 'Likely a scam';
    }
  }

  String get nameUpper => name.toUpperCase();
}

/// Full result of one scan: source text + fired signals + score + verdict
/// + grounded explanation (from LLM or deterministic fallback).
class ScanResult {
  final String sourceText;
  final List<SignalMatch> signals;
  final int score; // 0..100
  final Verdict verdict;
  final String explanation; // plain-language, grounded in [signals]
  final String whatToDo; // one-line action
  final DateTime scannedAt;
  final bool llmUsed; // false when deterministic fallback was used

  const ScanResult({
    required this.sourceText,
    required this.signals,
    required this.score,
    required this.verdict,
    required this.explanation,
    required this.whatToDo,
    required this.scannedAt,
    required this.llmUsed,
  });

  Map<String, dynamic> toJson() => {
        'sourceText': sourceText,
        'signals': signals.map((s) => s.toJson()).toList(),
        'score': score,
        'verdict': verdict.name,
        'explanation': explanation,
        'whatToDo': whatToDo,
        'scannedAt': scannedAt.toIso8601String(),
        'llmUsed': llmUsed,
      };

  factory ScanResult.fromJson(Map<String, dynamic> j) => ScanResult(
        sourceText: j['sourceText'] as String,
        signals: ((j['signals'] as List?) ?? const [])
            .map((e) => SignalMatch.fromJson(Map<String, dynamic>.from(e as Map)))
            .toList(),
        score: (j['score'] as num).toInt(),
        verdict: Verdict.values.firstWhere(
          (v) => v.name == (j['verdict'] as String),
          orElse: () => Verdict.safe,
        ),
        explanation: (j['explanation'] ?? '') as String,
        whatToDo: (j['whatToDo'] ?? '') as String,
        scannedAt: DateTime.tryParse((j['scannedAt'] ?? '') as String) ??
            DateTime.now(),
        llmUsed: (j['llmUsed'] ?? false) as bool,
      );
}
