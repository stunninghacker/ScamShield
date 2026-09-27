/// The RULE ENGINE — owns the verdict. Deterministic, pure Dart, offline.
///
/// Pipeline: run every detector -> composite impersonation check ->
/// cap link contribution -> sum -> clamp 0..100 -> floor at SUSPICIOUS
/// when at least one pattern fired -> DEMAND GATE (see analyze()) ->
/// map to Verdict.
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
  /// Powers the "WHY WE FLAGGED THIS" evidence view. These are the raw
  /// per-class weights and sum to the pre-gate score; the demand gate may
  /// then clamp a warn-only message down to 59 so score and verdict agree.
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

    // Fail-open fix: a message we found evidence in must never be reported
    // as SAFE. Any fired pattern puts the score at least at the SUSPICIOUS
    // threshold; the per-class breakdown above still shows exactly which
    // patterns were found (so the explanation can never invent one).
    if (signals.isNotEmpty && score < RuleThresholds.suspicious) {
      score = RuleThresholds.suspicious;
    }

    // DEMAND GATE — the verdict rubric (mirrored in
    // test/eval_harness_test.dart), so WARN and BLOCK are decided by what
    // the message ASKS FOR, not by how many words it uses:
    //   BLOCK  = it demands something (credential, remote control, a
    //            coercive threat, money) OR it couples an urgency threat
    //            with a link or a lure — that is the attack, in progress.
    //   WARN   = every other fired pattern (a lone link, a lone lure,
    //            brand + link, brand + callback). Evidence keeps stacking
    //            inside the band, but it cannot cross into BLOCK on its
    //            own: we do not block people on a bare URL.
    // The score is clamped into the band so `score/100` and the verdict
    // always agree; the breakdown stays the raw per-class weights (it is
    // evidence provenance, not a second score).
    final ids = signals.map((s) => s.id).toSet();
    final demand = ids.contains('SECRET_REQUEST') ||
        ids.contains('REMOTE_ACCESS') ||
        ids.contains('DIGITAL_ARREST') ||
        ids.contains('PAYMENT_PULL');
    final threatWithVector = ids.contains('URGENCY_THREAT') &&
        (ids.contains('LINK_RISK') ||
            ids.contains('REWARD_LURE') ||
            ids.contains('JOB_LURE'));
    if (!demand && !threatWithVector && score >= RuleThresholds.dangerous) {
      score = RuleThresholds.dangerous - 1;
    }

    final verdict = score >= RuleThresholds.dangerous
        ? Verdict.dangerous
        : score >= RuleThresholds.suspicious
            ? Verdict.suspicious
            : Verdict.safe;

    return EngineResult(
        signals: signals,
        score: score,
        verdict: verdict,
        breakdown: breakdown);
  }
}
