/// The RULE ENGINE — owns the verdict. Deterministic, pure Dart, offline.
///
/// Pipeline: run every detector -> composite impersonation check ->
/// cap link contribution -> sum -> clamp 0..100 -> map to Verdict.
///
/// The LLM NEVER calls this file and NEVER changes its output.
library;

import '../models/verdict.dart';
import '../models/signal_match.dart';
import 'constants.dart';
import 'signals.dart';

class EngineResult {
  final List<SignalMatch> signals;
  final int score;
  final Verdict verdict;

  /// Explainable contribution per signal class, e.g. {LINK_RISK: 55}.
  /// Powers the "WHY WE FLAGGED THIS" evidence view. Sums to [score].
  final Map<String, int> breakdown;
  const EngineResult({
    required this.signals,
    required this.score,
    required this.verdict,
    this.breakdown = const {},
  });
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
    final remote = detectRemoteAccess(text);
    final job = detectJobLure(text);
    final arrest = detectDigitalArrest(text);

    final others = [
      ...links,
      ...secrets,
      ...urgency,
      ...reward,
      ...payment,
      ...callback,
      ...remote,
      ...job,
      ...arrest,
    ];
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
    final breakdown = <String, int>{};
    if (linkScore > 0) breakdown['LINK_RISK'] = linkScore;
    void add(String id, List<SignalMatch> hits, int weight) {
      if (hits.isNotEmpty) {
        score += weight;
        breakdown[id] = weight;
      }
    }

    add('SECRET_REQUEST', secrets, RuleWeights.secretRequest);
    add('URGENCY_THREAT', urgency, RuleWeights.urgencyThreat);
    add('REWARD_LURE', reward, RuleWeights.rewardLure);
    add('PAYMENT_PULL', payment, RuleWeights.paymentPull);
    add('CALLBACK', callback, RuleWeights.callback);
    add('REMOTE_ACCESS', remote, RuleWeights.remoteAccess);
    add('JOB_LURE', job, RuleWeights.jobLure);
    add('DIGITAL_ARREST', arrest, RuleWeights.digitalArrest);
    // Impersonation last so the map reads naturally in the UI.
    add('IMPERSONATION', impersonation, RuleWeights.impersonation);

    if (score > 100) score = 100;
    if (score < 0) score = 0;

    final verdict = score >= RuleThresholds.dangerous
        ? Verdict.dangerous
        : score >= RuleThresholds.suspicious
            ? Verdict.suspicious
            : Verdict.safe;

    final signals = [
      ...cappedLinks,
      ...secrets,
      ...urgency,
      ...reward,
      ...payment,
      ...callback,
      ...remote,
      ...job,
      ...arrest,
      ...impersonation,
    ]..sort((a, b) => a.start.compareTo(b.start));

    return EngineResult(
        signals: signals,
        score: score,
        verdict: verdict,
        breakdown: breakdown);
  }
}
