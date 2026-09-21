/// Evidence-first reporting: category, calibrated confidence, and labeled
/// per-signal contributions. Pure Dart, deterministic.
///
/// Honesty rules (see SPEC §18/§37): the score is labeled "ScamShield risk
/// score (internal heuristic)" everywhere it is shown, confidence is a
/// calibrated heuristic — never certainty — and empty scans report no
/// confidence at all.
library;

import '../models/signal_match.dart';

/// Human label per signal class for evidence views.
const signalLabels = <String, String>{
  'LINK_RISK': 'Suspicious link',
  'SECRET_REQUEST': 'Secret-code request',
  'URGENCY_THREAT': 'Urgency / threat',
  'REWARD_LURE': 'Prize / refund lure',
  'PAYMENT_PULL': 'Payment request',
  'CALLBACK': 'Callback number',
  'REMOTE_ACCESS': 'Remote-access trap',
  'JOB_LURE': 'Fake job lure',
  'DIGITAL_ARREST': 'Digital-arrest threat',
  'IMPERSONATION': 'Authority impersonation',
};

class Contribution {
  final String id;
  final String label;
  final int weight;
  const Contribution(this.id, this.label, this.weight);
}

/// Sorted largest-first contributions from an engine breakdown map.
List<Contribution> contributionsFor(Map<String, int> breakdown) {
  final out = breakdown.entries
      .map((e) => Contribution(
          e.key, signalLabels[e.key] ?? e.key, e.value))
      .toList()
    ..sort((a, b) => b.weight.compareTo(a.weight));
  return out;
}

/// Deterministic category from fired signal classes (first match wins,
/// ordered most-specific first).
String categoryFor(List<SignalMatch> signals) {
  if (signals.isEmpty) return 'Genuine';
  final ids = signals.map((s) => s.id).toSet();
  if (ids.contains('DIGITAL_ARREST')) return 'Digital Arrest';
  if (ids.contains('JOB_LURE')) return 'Job / Task Scam';
  if (ids.contains('REMOTE_ACCESS')) return 'Tech-support / Remote-access';
  if (ids.contains('REWARD_LURE') && ids.contains('PAYMENT_PULL')) {
    return 'Lottery / Refund Scam';
  }
  if (ids.contains('SECRET_REQUEST') &&
      (ids.contains('URGENCY_THREAT') || ids.contains('LINK_RISK'))) {
    return 'Banking / OTP Scam';
  }
  if (ids.contains('PAYMENT_PULL')) return 'Payment Scam';
  if (ids.contains('LINK_RISK')) return 'Phishing Link';
  if (ids.contains('REWARD_LURE')) return 'Prize Lure';
  if (ids.contains('URGENCY_THREAT')) return 'Threat / Extortion';
  return 'Suspicious Message';
}

/// Calibrated heuristic confidence in [0.0, 0.95]. Returns 0.0 when nothing
/// fired (UI hides the meter). NEVER 1.0 — we do not claim certainty.
double confidenceFor(int score, {required bool hasSignals}) {
  if (!hasSignals || score <= 0) return 0.0;
  return (0.5 + score / 200).clamp(0.0, 0.95);
}

/// AI-context tags: semantic reading of signal COMBINATIONS for the
/// fusion layer. Deterministic and heuristic — shown as "AI context
/// (heuristic)" and fed to the LLM prompt so explanations stay grounded.
List<String> contextTagsFor(List<SignalMatch> signals) {
  if (signals.isEmpty) return const [];
  final ids = signals.map((s) => s.id).toSet();
  final tags = <String>[];
  void add(bool cond, String tag) {
    if (cond) tags.add(tag);
  }

  add(ids.contains('IMPERSONATION') &&
      (ids.contains('LINK_RISK') || ids.contains('CALLBACK')),
      'Authority impersonation');
  add(ids.contains('SECRET_REQUEST') && ids.contains('URGENCY_THREAT'),
      'Financial pressure');
  add(ids.contains('SECRET_REQUEST') &&
      (ids.contains('PAYMENT_PULL') || ids.contains('LINK_RISK')),
      'Credential harvesting');
  add(ids.contains('REWARD_LURE') && ids.contains('PAYMENT_PULL'),
      'Advance-fee lure');
  add(ids.contains('DIGITAL_ARREST'), 'Coercive video-call threat');
  add(ids.contains('REMOTE_ACCESS'), 'Device-takeover attempt');
  add(ids.contains('JOB_LURE'), 'Recruitment fraud pattern');
  add(ids.contains('CALLBACK') && ids.contains('URGENCY_THREAT'),
      'Callback trap');
  return tags;
}
