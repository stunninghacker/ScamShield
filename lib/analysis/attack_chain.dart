/// Evidence-first attack-chain architecture (deterministic, offline).
///
/// The rule engine is UNCHANGED and still owns the verdict. This layer turns
/// its output into an ordered, serializable attack story for ONE message:
///
///   spans (SignalMatch) → one DetectedSignal per class → ordered ChainSteps
///   → ScamFamily → SignalChain
///
/// (The multi-MESSAGE chain across Timeline stages lives in stages.dart and
/// is untouched — this is the within-message progression: lure → pressure →
/// vector → harvest → cash-out.)
///
/// Guarantees:
///  - one contribution per signal class, ever (no duplicate counting);
///  - negation handling lives in the engine and is preserved untouched;
///  - strengths are documented heuristics in (0, 0.95] — never certainty;
///  - every output round-trips through JSON for Timeline/Command Center.
library;

import '../models/verdict.dart';
import '../models/signal_match.dart';
import 'verdict_report.dart' show signalLabels;

/// One fired signal class with its evidence, contribution and strength.
class DetectedSignal {
  final String id;
  final String label;
  final List<String> evidence; // exact matched substrings (unique, in order)
  final int start; // offset of first span
  final int end; // offset of first span
  final int contribution; // score contribution (per-class weight, once)
  final double strength; // evidence strength heuristic, 0..0.95
  final String detail;

  const DetectedSignal({
    required this.id,
    required this.label,
    required this.evidence,
    required this.start,
    required this.end,
    required this.contribution,
    required this.strength,
    this.detail = '',
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'label': label,
        'evidence': evidence,
        'start': start,
        'end': end,
        'contribution': contribution,
        'strength': strength,
        'detail': detail,
      };

  factory DetectedSignal.fromJson(Map<String, dynamic> j) =>
      DetectedSignal(
        id: '${j['id']}',
        label: '${j['label']}',
        evidence:
            ((j['evidence'] as List?) ?? const []).map((e) => '$e').toList(),
        start: (j['start'] as num?)?.toInt() ?? 0,
        end: (j['end'] as num?)?.toInt() ?? 0,
        contribution: (j['contribution'] as num?)?.toInt() ?? 0,
        strength: (j['strength'] as num?)?.toDouble() ?? 0.0,
        detail: '${j['detail'] ?? ''}',
      );
}

enum ScamFamily {
  phishing,
  bankingFraud,
  digitalArrest,
  jobScam,
  remoteAccess,
  deliveryScam,
  investmentScam,
  accountTakeover,
  none,
}

extension ScamFamilyX on ScamFamily {
  String get label {
    switch (this) {
      case ScamFamily.phishing:
        return 'Phishing';
      case ScamFamily.bankingFraud:
        return 'Banking fraud';
      case ScamFamily.digitalArrest:
        return 'Digital arrest';
      case ScamFamily.jobScam:
        return 'Job scam';
      case ScamFamily.remoteAccess:
        return 'Remote access';
      case ScamFamily.deliveryScam:
        return 'Delivery scam';
      case ScamFamily.investmentScam:
        return 'Investment scam';
      case ScamFamily.accountTakeover:
        return 'Account takeover';
      case ScamFamily.none:
        return 'No scam pattern';
    }
  }
}

/// Canonical attack progression: lure/trust → pressure → vector →
/// harvest → cash-out. Independent of text order.
const chainOrder = <String, int>{
  'IMPERSONATION': 0,
  'URGENCY_THREAT': 1,
  'DIGITAL_ARREST': 1,
  'REWARD_LURE': 2,
  'JOB_LURE': 2,
  'LINK_RISK': 3,
  'SECRET_REQUEST': 4,
  'CALLBACK': 5,
  'PAYMENT_PULL': 6,
  'REMOTE_ACCESS': 6,
};

const stageHints = <int, String>{
  0: 'Trust',
  1: 'Pressure',
  2: 'Lure',
  3: 'Vector',
  4: 'Harvest',
  5: 'Callback',
  6: 'Cash-out',
};

/// Evidence-strength heuristic. Base 0.55 + up to +0.16 for repeated
/// independent spans + a quality boost for high-fidelity indicators
/// (lookalike domain, direct credential demand, UPI payee). Clamped to
/// 0.95 — strong evidence, never proof.
double strengthFor(String id, List<SignalMatch> spans) {
  var s = 0.55;
  final extra = (spans.length - 1).clamp(0, 2);
  s += extra * 0.08;
  switch (id) {
    case 'LINK_RISK':
      if (spans.any((m) => m.detail.contains('lookalike'))) {
        s += 0.15;
      } else if (spans.any((m) =>
          m.detail.contains('shortener') ||
          m.detail.contains('ip-host'))) {
        s += 0.1;
      } else {
        s += 0.05;
      }
      break;
    case 'SECRET_REQUEST':
      s += 0.15;
      break;
    case 'PAYMENT_PULL':
      s += spans.any((m) => m.detail.startsWith('upi:'))
          ? 0.15
          : 0.05;
      break;
    case 'DIGITAL_ARREST':
      s += 0.15;
      break;
    default:
      s += 0.1;
  }
  return s.clamp(0.0, 0.95);
}

/// Groups spans into exactly one DetectedSignal per class. Repeated
/// keywords contribute once; extra spans only raise strength.
List<DetectedSignal> buildEvidence(
    List<SignalMatch> signals, Map<String, int> breakdown) {
  final byId = <String, List<SignalMatch>>{};
  for (final s in signals) {
    byId.putIfAbsent(s.id, () => []).add(s);
  }
  final out = <DetectedSignal>[];
  for (final entry in byId.entries) {
    final spans = entry.value
      ..sort((a, b) => a.start.compareTo(b.start));
    final seen = <String>[];
    for (final m in spans) {
      if (!seen.contains(m.matchedText)) seen.add(m.matchedText);
    }
    out.add(DetectedSignal(
      id: entry.key,
      label: signalLabels[entry.key] ?? entry.key,
      evidence: seen,
      start: spans.first.start,
      end: spans.first.end,
      contribution: breakdown[entry.key] ?? 0,
      strength: strengthFor(entry.key, spans),
      detail: spans.first.detail,
    ));
  }
  return out;
}

bool _has(Set<String> ids, String id) => ids.contains(id);

bool _evidenceHas(List<SignalMatch> signals, RegExp re) =>
    signals.any((s) => re.hasMatch(s.matchedText.toLowerCase()));

final _bankEv = RegExp(
    r'sbi|hdfc|icici|axis|kotak|pnb|rbi|\bbank\b|income.?tax');
final _deliveryEv =
    RegExp(r'courier|delivery|\bpost\b|parcel|package|dhl|fedex');
final _investEv = RegExp(
    r'invest|trading|demat|crypto|profit|guaranteed.?return|double.{0,10}money|\breturns?\b');

/// Family from signal COMBINATIONS (first match wins — order is the spec).
/// Inspects only fired evidence text; changes no scores, adds no network.
ScamFamily familyFor(List<SignalMatch> signals) {
  if (signals.isEmpty) return ScamFamily.none;
  final ids = signals.map((s) => s.id).toSet();
  if (_has(ids, 'DIGITAL_ARREST')) return ScamFamily.digitalArrest;
  if (_has(ids, 'JOB_LURE')) return ScamFamily.jobScam;
  if (_has(ids, 'SECRET_REQUEST') && _has(ids, 'REMOTE_ACCESS')) {
    return ScamFamily.accountTakeover;
  }
  if (_has(ids, 'REMOTE_ACCESS')) return ScamFamily.remoteAccess;
  if (_has(ids, 'SECRET_REQUEST') && _has(ids, 'URGENCY_THREAT')) {
    return ScamFamily.bankingFraud;
  }
  if (_evidenceHas(signals, _deliveryEv) &&
      (_has(ids, 'LINK_RISK') ||
          _has(ids, 'CALLBACK') ||
          _has(ids, 'PAYMENT_PULL'))) {
    return ScamFamily.deliveryScam;
  }
  if (_evidenceHas(signals, _investEv) &&
      (_has(ids, 'REWARD_LURE') || _has(ids, 'PAYMENT_PULL'))) {
    return ScamFamily.investmentScam;
  }
  if (_has(ids, 'SECRET_REQUEST') && _has(ids, 'LINK_RISK')) {
    return ScamFamily.accountTakeover;
  }
  if (_has(ids, 'SECRET_REQUEST')) return ScamFamily.accountTakeover;
  if (_has(ids, 'REWARD_LURE') && _has(ids, 'PAYMENT_PULL')) {
    return ScamFamily.bankingFraud;
  }
  if (_evidenceHas(signals, _bankEv) &&
      (_has(ids, 'URGENCY_THREAT') ||
          _has(ids, 'LINK_RISK') ||
          _has(ids, 'PAYMENT_PULL') ||
          _has(ids, 'CALLBACK'))) {
    return ScamFamily.bankingFraud;
  }
  if (_has(ids, 'PAYMENT_PULL')) return ScamFamily.bankingFraud;
  return ScamFamily.phishing;
}

/// One ordered step of the attack story.
class ChainStep {
  final DetectedSignal signal;
  int get order => chainOrder[signal.id] ?? 99;
  String get stage => stageHints[order] ?? 'Signal';
  const ChainStep(this.signal);

  Map<String, dynamic> toJson() => {
        ...signal.toJson(),
        'order': order,
        'stage': stage,
      };
}

/// The full ordered, serializable attack story for one message.
class SignalChain {
  final ScamFamily family;
  final Verdict verdict;
  final int score;
  final List<ChainStep> steps;

  SignalChain({
    required this.family,
    required this.verdict,
    required this.score,
    required List<ChainStep> steps,
  }) : steps = List.unmodifiable(steps);

  Map<String, dynamic> toJson() => {
        'family': family.name,
        'familyLabel': family.label,
        'verdict': verdict.name,
        'score': score,
        'steps': steps.map((s) => s.toJson()).toList(),
      };
}

/// Builds the chain from engine output. Steps sorted by canonical attack
/// order (ties broken by signal id) — never by text position.
SignalChain buildSignalChain({
  required List<SignalMatch> signals,
  required Map<String, int> breakdown,
  required Verdict verdict,
  required int score,
}) {
  final steps = buildEvidence(signals, breakdown)
      .map(ChainStep.new)
      .toList()
    ..sort((a, b) {
      final c = a.order.compareTo(b.order);
      return c != 0 ? c : a.signal.id.compareTo(b.signal.id);
    });
  return SignalChain(
    family: familyFor(signals),
    verdict: verdict,
    score: score,
    steps: steps,
  );
}

