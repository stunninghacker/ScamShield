/// The RULE ENGINE — owns the verdict. Deterministic, pure Dart, offline.
///
/// Pipeline: run every detector -> composite impersonation check ->
/// cap link contribution -> sum -> clamp 0..100 -> map to Verdict.
///
/// The LLM NEVER calls this file and NEVER changes its output.
library;

import '../models/scan_result.dart';
import '../models/signal_match.dart';
import 'constants.dart';
import 'signals.dart';

class EngineResult {
  final List<SignalMatch> signals;
  final int score;
  final Verdict verdict;
  const EngineResult(
      {required this.signals, required this.score, required this.verdict});
}

class ScamEngine {
  const ScamEngine();

  EngineResult analyze(String rawText) {
    final text = rawText.trim();
    if (text.isEmpty) {
      return const EngineResult(signals: [], score: 0, verdict: Verdict.safe);
    }

    final links = detectLinks(text);
    final secrets = detectSecretRequest(text);
    final urgency = detectUrgency(text);
    final reward = detectReward(text);
    final payment = detectPaymentPull(text);
    final callback = detectCallback(text);

    final others = [...links, ...secrets, ...urgency, ...reward, ...payment, ...callback];
    final impersonation =
        detectImpersonation(text, otherSignalsNonEmpty: others.isNotEmpty);

    // Scoring is per-CLASS (predictable for demo), spans stay per-OCCURRENCE
    // for UI provenance. I.e. three "winner" hits highlight three times but
    // contribute RuleWeights.rewardLure once. Links are the exception: each
    // URL contributes, capped at RuleWeights.linkCap total.
    var linkScore = links.fold<int>(0, (a, s) => a + s.weight);
    final cappedLinks = links;
    if (linkScore > RuleWeights.linkCap && links.isNotEmpty) {
      linkScore = RuleWeights.linkCap;
    }

    var score = linkScore;
    if (secrets.isNotEmpty) score += RuleWeights.secretRequest;
    if (urgency.isNotEmpty) score += RuleWeights.urgencyThreat;
    if (reward.isNotEmpty) score += RuleWeights.rewardLure;
    if (payment.isNotEmpty) score += RuleWeights.paymentPull;
    if (callback.isNotEmpty) score += RuleWeights.callback;
    if (impersonation.isNotEmpty) score += RuleWeights.impersonation;

    if (score > 100) score = 100;
    if (score < 0) score = 0;

    final verdict = score >= RuleThresholds.dangerous
        ? Verdict.dangerous
        : score >= RuleThresholds.suspicious
            ? Verdict.suspicious
            : Verdict.safe;

    final signals = [...cappedLinks, ...secrets, ...urgency, ...reward, ...payment, ...callback, ...impersonation]
      ..sort((a, b) => a.start.compareTo(b.start));

    return EngineResult(signals: signals, score: score, verdict: verdict);
  }
}
