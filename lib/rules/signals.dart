/// Pure-Dart signal detectors. Every function is deterministic, offline,
/// and returns exact character offsets so the UI can highlight provenance.
///
/// No LLM, no network, no randomness — unit-tested in test/rules_test.dart.
library;

import '../models/signal_match.dart';
import 'constants.dart';

SignalMatch _m({
  required String id,
  required String label,
  required int weight,
  required String source,
  required int start,
  required int end,
  String detail = '',
}) =>
    SignalMatch(
      id: id,
      label: label,
      weight: weight,
      matchedText: source.substring(start, end),
      start: start,
      end: end,
      detail: detail,
    );

List<RegExpMatch> _all(RegExp re, String text) => re.allMatches(text).toList();

// ---------------------------------------------------------------------------
// LINK_RISK
// ---------------------------------------------------------------------------

/// Matches http(s)://... and www.... URLs, trims trailing punctuation.
final _urlRe = RegExp(r'(?:https?://|www\.)[^\s<>"' r"']+", caseSensitive: false);

String _trimUrl(String raw) {
  var s = raw;
  while (s.isNotEmpty && '.,;:!?)]}'.contains(s[s.length - 1])) {
    s = s.substring(0, s.length - 1);
  }
  return s;
}

String _hostOf(String url) {
  var u = url.toLowerCase();
  u = u.replaceFirst(RegExp(r'^https?://'), '');
  u = u.replaceFirst(RegExp(r'^www\.'), '');
  final slash = u.indexOf('/');
  if (slash != -1) u = u.substring(0, slash);
  final q = u.indexOf('?');
  if (q != -1) u = u.substring(0, q);
  final at = u.indexOf('@'); // userinfo? take last part
  if (at != -1) u = u.substring(at + 1);
  final colon = u.indexOf(':');
  if (colon != -1) u = u.substring(0, colon);
  return u;
}

String _tldOf(String host) {
  final parts = host.split('.');
  return parts.isEmpty ? '' : parts.last;
}

bool _isTrustedHost(String host) {
  if (trustedHosts.contains(host)) return true;
  // allow subdomains of trusted roots, e.g. www.onlinesbi.com
  for (final t in trustedHosts) {
    if (host == t || host.endsWith('.$t')) return true;
  }
  return false;
}

bool _isShortener(String host) =>
    shortenerHosts.contains(host) ||
    shortenerHosts.any((s) => host == s || host.endsWith('.$s'));

bool _isIpHost(String host) =>
    RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(host) ||
    RegExp(r'^\[[0-9a-f:]+\]$').hasMatch(host);

bool _isLookalike(String host) {
  if (_isTrustedHost(host)) return false;
  final h = host.toLowerCase();
  final hasBrand = brandKeywords.any((b) => h.contains(b));
  if (!hasBrand) return false;
  // Brand appears in a non-trusted host => lookalike if any shady indicator,
  // OR unconditionally when host contains a hyphen (sbi-verify.xyz pattern).
  final tld = _tldOf(h);
  if (suspiciousTlds.contains(tld)) return true;
  if (h.contains('-')) return true;
  // Brand + non-standard TLD (not .in/.com/.co.in/.gov.in/.org.in) => flag.
  const okTlds = {'in', 'com', 'co', 'gov', 'org', 'net'};
  if (!okTlds.contains(tld)) return true;
  return true; // brand in untrusted host is enough to warn
}

/// One SignalMatch per URL, weight = base + boosts (capped by caller).
List<SignalMatch> detectLinks(String text) {
  final out = <SignalMatch>[];
  for (final m in _all(_urlRe, text)) {
    var raw = m.group(0)!;
    final trimmed = _trimUrl(raw);
    final trimDelta = raw.length - trimmed.length;
    final end = m.end - trimDelta;
    final start = m.start;
    if (trimmed.length < 5) continue;

    final lower = trimmed.toLowerCase();
    final host = _hostOf(trimmed);
    var w = RuleWeights.linkBase;
    final reasons = <String>['url'];

    if (lower.startsWith('http://')) {
      w += RuleWeights.linkHttp;
      reasons.add('no-https');
    }
    if (_isShortener(host)) {
      w += RuleWeights.linkShortener;
      reasons.add('shortener:$host');
    }
    if (_isIpHost(host)) {
      w += RuleWeights.linkIpHost;
      reasons.add('ip-host');
    }
    if (_isLookalike(host)) {
      w += RuleWeights.linkLookalike;
      reasons.add('lookalike:$host');
    }

    out.add(_m(
      id: 'LINK_RISK',
      label: 'Suspicious link',
      weight: w,
      source: text,
      start: start,
      end: end,
      detail: reasons.join(', '),
    ));
  }
  return out;
}

// ---------------------------------------------------------------------------
// SECRET_REQUEST
// ---------------------------------------------------------------------------

final _secretRes = <RegExp>[
  RegExp(r'\botp\b', caseSensitive: false),
  RegExp(r'\bupi\s*pin\b', caseSensitive: false),
  RegExp(r'\batm\s*pin\b', caseSensitive: false),
  RegExp(r'\bcvv\b', caseSensitive: false),
  RegExp(r'\bpassword\b', caseSensitive: false),
  RegExp(r'\bpin\s*number\b', caseSensitive: false),
  RegExp(r'\bcard\s*(number|details|no\.?)\b', caseSensitive: false),
  RegExp(r'\bcredit\s*card\b', caseSensitive: false),
  RegExp(r'\bdebit\s*card\b', caseSensitive: false),
  RegExp(r'share\s+(the\s+|your\s+|this\s+)?(otp|code|pin|cvv|password)',
      caseSensitive: false),
  RegExp(r'enter\s+(your\s+)?(otp|pin|cvv|password|card)',
      caseSensitive: false),
  RegExp(r'send\s+(me\s+|us\s+)?(your\s+)?(otp|pin|cvv|password)',
      caseSensitive: false),
];

List<SignalMatch> detectSecretRequest(String text) {
  final out = <SignalMatch>[];
  final scan = _withoutUrls(text);
  for (final re in _secretRes) {
    for (final m in _all(re, scan)) {
      out.add(_m(
        id: 'SECRET_REQUEST',
        label: 'Asks for secret code',
        weight: RuleWeights.secretRequest,
        source: text,
        start: m.start,
        end: m.end,
        detail: 'secret:${m.group(0)}',
      ));
    }
  }
  _dedupe(out);
  return out;
}

// ---------------------------------------------------------------------------
// URGENCY_THREAT
// ---------------------------------------------------------------------------

final _urgencyRes = <RegExp>[
  RegExp(r'account\s+(will\s+be\s+)?(blocked|suspended|frozen|closed)',
      caseSensitive: false),
  RegExp(r'\bkyc\b.{0,20}(expired|expiring|suspended|blocked)',
      caseSensitive: false),
  RegExp(r'within\s+\d+\s*(hours?|minutes?|days?)', caseSensitive: false),
  RegExp(r'\bimmediately\b', caseSensitive: false),
  RegExp(r'\blast\s+warning\b', caseSensitive: false),
  RegExp(r'\blegal\s+action\b', caseSensitive: false),
  RegExp(r'\burgent\b', caseSensitive: false),
  RegExp(r'verify\s+(immediately|now)', caseSensitive: false),
  RegExp(r'\bsuspended\b', caseSensitive: false),
  RegExp(r'\bblocked\b', caseSensitive: false),
];

List<SignalMatch> detectUrgency(String text) {
  final out = <SignalMatch>[];
  final scan = _withoutUrls(text);
  for (final re in _urgencyRes) {
    for (final m in _all(re, scan)) {
      out.add(_m(
        id: 'URGENCY_THREAT',
        label: 'Urgency / threat',
        weight: RuleWeights.urgencyThreat,
        source: text,
        start: m.start,
        end: m.end,
        detail: 'urgency:${m.group(0)}',
      ));
    }
  }
  _dedupe(out);
  return out;
}

// ---------------------------------------------------------------------------
// REWARD_LURE
// ---------------------------------------------------------------------------

final _rewardRes = <RegExp>[
  RegExp(r'you\s+(have\s+)?won\b', caseSensitive: false),
  RegExp(r'\blottery\b', caseSensitive: false),
  RegExp(r'\blucky\s+winner\b', caseSensitive: false),
  RegExp(r'\bcashback\b', caseSensitive: false),
  RegExp(r'\brefund\s*(pending|approved|initiated)?\b', caseSensitive: false),
  RegExp(r'claim\s+(your\s+)?(prize|reward|cashback|refund)',
      caseSensitive: false),
  RegExp(r'\bprize\b', caseSensitive: false),
  RegExp(r'\bkbc\b', caseSensitive: false),
  RegExp(r'\bwinner\b', caseSensitive: false),
  RegExp(r'congratulations', caseSensitive: false),
];

List<SignalMatch> detectReward(String text) {
  final out = <SignalMatch>[];
  // Ignore keywords inside URLs / UPI handles (covered by LINK/PAYMENT).
  final scan = _maskRanges(
      text, [..._all(_urlRe, text), ..._all(_upiRe, text)]);
  for (final re in _rewardRes) {
    for (final m in _all(re, scan)) {
      out.add(_m(
        id: 'REWARD_LURE',
        label: 'Prize / refund lure',
        weight: RuleWeights.rewardLure,
        source: text,
        start: m.start,
        end: m.end,
        detail: 'reward:${m.group(0)}',
      ));
    }
  }
  _dedupe(out);
  return out;
}

// ---------------------------------------------------------------------------
// PAYMENT_PULL
// ---------------------------------------------------------------------------

final _upiRe =
    RegExp(r'[A-Za-z0-9._-]{2,}@(okhdfcbank|ybl|paytm|okicici|okaxis|oksbi|upi|ibl)',
        caseSensitive: false);

final _paymentRes = <RegExp>[
  RegExp(r'pay\s*(₹|rs\.?\s*\d[\d,]*)', caseSensitive: false),
  RegExp(r'scan\s+(this\s+)?(qr|code)', caseSensitive: false),
  RegExp(r'send\s+money\s+to', caseSensitive: false),
  RegExp(r'processing\s*fee', caseSensitive: false),
  RegExp(r'pay\s+(a\s+|the\s+)?(fee|amount|now)', caseSensitive: false),
  RegExp(r'\bupi\b.{0,20}(pay|send|id)', caseSensitive: false),
];

List<SignalMatch> detectPaymentPull(String text) {
  final out = <SignalMatch>[];
  for (final m in _all(_upiRe, text)) {
    out.add(_m(
      id: 'PAYMENT_PULL',
      label: 'Asks for payment (UPI)',
      weight: RuleWeights.paymentPull,
      source: text,
      start: m.start,
      end: m.end,
      detail: 'upi:${m.group(0)}',
    ));
  }
  for (final re in _paymentRes) {
    for (final m in _all(re, _withoutUrls(text))) {
      out.add(_m(
        id: 'PAYMENT_PULL',
        label: 'Asks for payment',
        weight: RuleWeights.paymentPull,
        source: text,
        start: m.start,
        end: m.end,
        detail: 'payment:${m.group(0)}',
      ));
    }
  }
  _dedupe(out);
  return out;
}

// ---------------------------------------------------------------------------
// CALLBACK — phone number + call-to-action language
// ---------------------------------------------------------------------------

final _callCueRe = RegExp(
    r'\bcall\b|contact|helpline|customer\s*care|toll[\s-]?free|call\s+now|reach\s+us',
    caseSensitive: false);

final _phoneRe = RegExp(
  r'(?:\+91[\s-]?)?(?:1800[\s-]?\d{3}[\s-]?\d{3,4}|\d{5}[\s-]?\d{5}|\d{10})',
);

List<SignalMatch> detectCallback(String text) {
  if (!_callCueRe.hasMatch(text)) return const [];
  final out = <SignalMatch>[];
  for (final m in _all(_phoneRe, text)) {
    // Guard: skip matches that are clearly amounts/years (contain , or are
    // part of a longer digit run). Regex already excludes commas.
    out.add(_m(
      id: 'CALLBACK',
      label: 'Callback number',
      weight: RuleWeights.callback,
      source: text,
      start: m.start,
      end: m.end,
      detail: 'callback:${m.group(0)}',
    ));
  }
  _dedupe(out);
  return out;
}

// ---------------------------------------------------------------------------
// IMPERSONATION — brand mention COMBINED with any other signal (composite)
// ---------------------------------------------------------------------------

final _impersonationRe = RegExp(
  r'\bsbi\b|\bhdfc\b|\bicici\b|\baxis\b|\bkotak\b|\bpnb\b|\brbi\b|'
  r'income\s*tax|india\s*post|courier|delivery|\bdhl\b|\bfedex\b|\bekart\b|'
  r'\bdelhivery\b|\bbluedart\b|customs|\bpolice\b|\bcbi\b|\bkbc\b',
  caseSensitive: false,
);

/// Fires ONLY when [otherSignalsNonEmpty] is true — a lone "SBI" in a
/// genuine transaction alert must NOT flag.
///
/// NOTE: URLs are stripped before matching so a brand word inside a link
/// (e.g. "delivery" in delivery-update.com) doesn't inflate the count —
/// the link itself already carries LINK_RISK weight.
List<SignalMatch> detectImpersonation(String text,
    {required bool otherSignalsNonEmpty}) {
  if (!otherSignalsNonEmpty) return const [];
  // Strip URLs for the search, but report offsets in the ORIGINAL text.
  // Approach: blank out URL chars (keep length) so offsets stay valid.
  var masked = text;
  for (final m in _all(_urlRe, text)) {
    masked = masked.replaceRange(m.start, m.end, ' ' * (m.end - m.start));
  }
  final out = <SignalMatch>[];
  for (final m in _all(_impersonationRe, masked)) {
    out.add(_m(
      id: 'IMPERSONATION',
      label: 'Impersonates bank / govt / courier',
      weight: RuleWeights.impersonation,
      source: text,
      start: m.start,
      end: m.end,
      detail: 'brand:${text.substring(m.start, m.end)}',
    ));
  }
  _dedupe(out);
  return out;
}

/// Blanks out [ranges] (replaces with spaces, keeps length) so detectors
/// don't fire *inside* URLs/UPI handles — the link itself already carries
/// LINK_RISK / PAYMENT_PULL weight. Offsets stay valid for the original text.
String _maskRanges(String text, List<RegExpMatch> ms) {
  final chars = text.split('');
  for (final m in ms) {
    for (var i = m.start; i < m.end && i < chars.length; i++) {
      chars[i] = ' ';
    }
  }
  return chars.join();
}

/// Text with URL spans blanked (same length, same offsets).
String _withoutUrls(String text) => _maskRanges(text, _all(_urlRe, text));

void _dedupe(List<SignalMatch> list) {  // Remove exact-duplicate spans (two patterns matching same offsets),
  // keep first. Sort by start for stable UI highlighting.
  final seen = <String>{};
  list.removeWhere((s) {
    final k = '${s.start}:${s.end}:${s.id}';
    if (seen.contains(k)) return true;
    seen.add(k);
    return false;
  });
  list.sort((a, b) => a.start.compareTo(b.start));
}
