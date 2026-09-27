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
// Advisory / negation guards (shared by SECRET, REWARD, PAYMENT, REMOTE)
// ---------------------------------------------------------------------------

/// Negation words marking safety ADVICE rather than a demand.
/// Checked only in the same clause before the keyword.
final _advisoryNeg = RegExp(
    r"\b(never|don't|do not|does not|will never|won't|would never|beware|"
    r"not\s+share|if\s+(?:someone|anyone|somebody|anybody)\s+asks?|"
    r"is\s+(?:likely|probably)\s+a\s+scam|would\s+be\s+a\s+scam)\b",
    caseSensitive: false);

/// Advice that comes AFTER the keyword — "Your OTP is 7890, do not share
/// it". The pre-clause guard cannot see this, so the same clause is also
/// checked forward.
final _advisoryNegAfter = RegExp(
    r"\b(?:do\s+not|don't|never|not\s+supposed\s+to|should\s+not|shouldn't)"
    r"\s+(?:share|enter|reveal|give|tell|send|type|disclose)",
    caseSensitive: false);

/// True when offset [at] sits in a clause that argues AGAINST the action.
bool _isAdvisoryBefore(String scan, int at) {
  final winStart = (at - 48).clamp(0, scan.length);
  final clause = scan.substring(winStart, at).split(RegExp(r'[.!?\n]')).last;
  return _advisoryNeg.hasMatch(clause.toLowerCase());
}

/// True when the clause STARTING at offset [at] argues against the action.
bool _isAdvisoryAfter(String scan, int at) {
  final winEnd = (at + 72).clamp(at, scan.length);
  final clause = scan.substring(at, winEnd).split(RegExp(r'[.!?\n]')).first;
  return _advisoryNegAfter.hasMatch(clause);
}

// ---------------------------------------------------------------------------
// SECRET_REQUEST
// ---------------------------------------------------------------------------

final _passwordRe = RegExp(r'\bpassword\b', caseSensitive: false);

/// "password has been changed successfully" / "password was updated" —
/// a completed-change notification, not a demand for a secret.
final _notifyRe = RegExp(
    r'(?:has\s+been|was|were|is)\s+(?:changed|updated|modified|reset|replaced)'
    r'\b|successfully',
    caseSensitive: false);

bool _isChangeNotification(String scan, int from) {
  final winEnd = (from + 56).clamp(from, scan.length);
  final clause = scan.substring(from, winEnd).split(RegExp(r'[.!?\n]')).first;
  return _notifyRe.hasMatch(clause);
}

final _secretRes = <RegExp>[
  RegExp(r'\botp\b', caseSensitive: false),
  RegExp(r'\bupi\s*pin\b', caseSensitive: false),
  RegExp(r'\batm\s*pin\b', caseSensitive: false),
  RegExp(r'\bcvv\b', caseSensitive: false),
  _passwordRe,
  RegExp(r'\bpin\s*number\b', caseSensitive: false),
  RegExp(r'\bcard\s*(number|details|no\.?)\b', caseSensitive: false),
  // Bare "credit card" / "debit card" is a product NAME, not a request.
  // "Your HDFC credit card bill is due" must not fire — only an explicit
  // demand context ("share your credit card number") counts, and that is
  // already covered by the card-number / share / enter patterns below.
  RegExp(r'share\s+(the\s+|your\s+|this\s+)?(otp|code|pin|cvv|password)',
      caseSensitive: false),
  RegExp(r'enter\s+(your\s+)?(otp|pin|cvv|password|card)',
      caseSensitive: false),
  RegExp(r'send\s+(me\s+|us\s+)?(your\s+)?(otp|pin|cvv|password)',
      caseSensitive: false),
  RegExp(r'\bcredentials?\b', caseSensitive: false),
  RegExp(r'\bbank\s+details\b', caseSensitive: false),
  // "Your WhatsApp code is 918-273. Share it ..." — the ask verb and the
  // keyword sit in different sentences, so a bare keyword pattern is
  // required. The advisory guards below keep genuine OTP advice clean.
  RegExp(r'\b(?:verification|login|whatsapp|2fa|auth(?:entication)?|security)'
      r'\s+code\b',
      caseSensitive: false),
];

/// Strips negated share/enter phrases so [detectSecretRequest] can tell a
/// message that MENTIONS secrets safely ("Do not share this OTP with
/// anyone") from one that ASKS for them ("Share this OTP to verify").
final _negatedShareRe = RegExp(
    r"(?:do\s+not|don't|never|should\s+not|shouldn't|not\s+supposed\s+to)\s+"
    r'(?:share|enter|reveal|give|tell|send|type|disclose)',
    caseSensitive: false);
final _positiveAskRe = RegExp(
    r'\b(share|enter|send|provide|reply\s+with|type\s+in|give|submit)\b',
    caseSensitive: false);

/// Whole-message advisory: fires only when the text carries a negated
/// share/enter phrase AND no ask verb survives stripping it. The
/// clause-local guards cannot see "Your OTP for transaction is 8899. Do
/// not share this OTP with anyone" — the keyword clause has no negation.
bool _isPureAdvisory(String scan) {
  if (!_negatedShareRe.hasMatch(scan)) return false;
  return !_positiveAskRe.hasMatch(scan.replaceAll(_negatedShareRe, ' '));
}

List<SignalMatch> detectSecretRequest(String text) {
  final out = <SignalMatch>[];
  final scan = _withoutUrls(text);
  // Whole-message safety advice short-circuits every pattern: no ask verb
  // survives the negation, so nothing in this text demands a secret.
  if (_isPureAdvisory(scan)) return out;
  for (final re in _secretRes) {
    for (final m in _all(re, scan)) {
      // Advisory negation: "never share your OTP", "do not enter your
      // PIN" — safety advice mentioning secrets is not a request.
      // Only a negation in the SAME clause BEFORE the keyword suppresses,
      // so "Share your OTP. Never ignore this!" still fires.
      if (_isAdvisoryBefore(scan, m.start)) continue;
      // Forward guard: "Your OTP is 7890, do not share it with anyone".
      if (_isAdvisoryAfter(scan, m.end)) continue;
      // Completed-change notification reports an event, not a demand.
      if (identical(re, _passwordRe) && _isChangeNotification(scan, m.end)) {
        continue;
      }
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
  RegExp(r'account\s+(will\s+be\s+|is\s+|has\s+been\s+|was\s+)?'
      r'(blocked|suspended|frozen|closed|compromised|deactivated|locked|'
      r'disabled|deleted|flagged|at\s+risk|under\s+review)',
      caseSensitive: false),
  RegExp(r'\bkyc\b.{0,20}(expired|expiring|suspended|blocked)',
      caseSensitive: false),
  RegExp(r'within\s+\d+\s*(hours?|minutes?|days?)', caseSensitive: false),
  RegExp(r'\bimmediately\b', caseSensitive: false),
  RegExp(r'\blast\s+warning\b', caseSensitive: false),
  RegExp(r'\bfinal\s+notice\b', caseSensitive: false),
  RegExp(r'\blegal\s+action\b', caseSensitive: false),
  RegExp(r'\burgent\b', caseSensitive: false),
  RegExp(r'verify\s+(immediately|now)', caseSensitive: false),
  RegExp(r'\bsuspended\b', caseSensitive: false),
  RegExp(r'\bblocked\b', caseSensitive: false),
  // Fraud-alert language that the account-state patterns above miss.
  RegExp(r'\b(?:unauthorized|unauthorised)\s+'
      r'(?:login|logins|transaction|transactions|activity|access|attempt)',
      caseSensitive: false),
  RegExp(r'\bsuspicious\s+'
      r'(?:login|logins|activity|transaction|transactions|access)',
      caseSensitive: false),
  RegExp(r'\b(?:login|logged)\s+from\s+'
      r'(?:another|a\s+different)\s+(?:city|device|location|country)',
      caseSensitive: false),
  RegExp(r'\bcompromised\b', caseSensitive: false),
  RegExp(r'\bdeactivated\b', caseSensitive: false),
  RegExp(r'\bcloned\b', caseSensitive: false),
  RegExp(r'\bunder\s+investigation\b', caseSensitive: false),
  RegExp(r'\bbalance\s+is\s+low\b', caseSensitive: false),
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
  // A refund is only a LURE when it is pending / ready / needs an action.
  // "Your income tax refund issued" is a notification, not bait.
  RegExp(r'\brefund\s+(pending|approved|initiated|processing|ready|on\s+hold|'
      r'is\s+ready|has\s+been\s+approved)\b', caseSensitive: false),
  RegExp(r'\b(?:claim|receive|get|unlock|view|check|pending)\s+'
      r'(?:your\s+)?(?:\w+\s+)?refund\b', caseSensitive: false),
  RegExp(r'claim\s+(your\s+)?(prize|reward|cashback)',
      caseSensitive: false),
  // "... share OTP to claim" / "and get a reward" — the object of the
  // sentence is the bait even when it is not next to the verb.
  RegExp(r'\bto\s+claim\b', caseSensitive: false),
  RegExp(r'\bget\s+(?:a\s+)?(?:reward|bonus|gift|cashback)\b',
      caseSensitive: false),
  // "Invest Rs.5000 and get Rs.15000 back" — the multiplication IS the lure.
  RegExp(r'\b(?:get|earn)\s+(?:rs\.?|₹)\s*\d[\d,]*\s+back\b',
      caseSensitive: false),
  // "Earn Rs.15,000 weekly by doing tasks" — held-out miss showed the
  // percent-shaped earn pattern could not see an amount.
  RegExp(r'\bearn\s+(?:rs\.?|₹)\s*\d[\d,]*', caseSensitive: false),
  RegExp(r'\bprize\b', caseSensitive: false),
  RegExp(r'\bkbc\b', caseSensitive: false),
  RegExp(r'\bwinner\b', caseSensitive: false),
  RegExp(r'congratulations', caseSensitive: false),
  // Investment lures: guaranteed / multiplied / percentage returns.
  RegExp(r'guaranteed\s+(?:[^\s]+\s+){0,3}?(?:profits?|returns?)\b',
      caseSensitive: false),
  RegExp(r'\b(?:double|triple)\s+your\s+(?:money|investment|amount)',
      caseSensitive: false),
  RegExp(r'\b\d+(?:\.\d+)?x\s+(?:profits?|returns?|gains?)\b',
      caseSensitive: false),
  RegExp(r'\b(?:profits?|returns?)\s+in\s+\d+\s*(?:hours?|days?|weeks?|months?)',
      caseSensitive: false),
  RegExp(r'\bearn\s+\d+(?:\.\d+)?\s?%', caseSensitive: false),
  RegExp(r'\bearn\s+(?:daily|weekly|monthly|hourly|profits?|returns?|money)\b',
      caseSensitive: false),
  RegExp(r'\b(?:daily|weekly|monthly)\s+returns?\b', caseSensitive: false),
  RegExp(r'\bhigh\s+returns?\b', caseSensitive: false),
  RegExp(r'\brisk[-\s]free\s+(?:profits?|returns?)\b', caseSensitive: false),
  RegExp(r'\bdoubled\b', caseSensitive: false),
];

List<SignalMatch> detectReward(String text) {
  final out = <SignalMatch>[];
  // Ignore keywords inside URLs / UPI handles (covered by LINK/PAYMENT).
  final scan = _maskRanges(
      text, [..._all(_urlRe, text), ..._all(_upiRe, text)]);
  for (final re in _rewardRes) {
    for (final m in _all(re, scan)) {
      // "Do not pay any fee to claim a prize you did not enter" is advice.
      if (_isAdvisoryBefore(scan, m.start)) continue;
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
  RegExp(r'pay\s*(?:₹|rs\.?\s*\d[\d,]*)', caseSensitive: false),
  RegExp(r'send\s+(?:₹|rs\.?\s*)?\d[\d,]*', caseSensitive: false),
  RegExp(r'scan\s+(this\s+)?(qr|code)', caseSensitive: false),
  RegExp(r'send\s+money\s+to', caseSensitive: false),
  RegExp(r'processing\s*fee', caseSensitive: false),
  RegExp(r'pay\s+(a\s+|the\s+)?(fee|amount|now)', caseSensitive: false),
  // "pay the fine / pay a penalty / pay customs fee / pay clearance fee".
  // The gap allows filler words, amounts and hyphenated nouns so real
  // demands parse: "Pay the Rs.19 postage charge", "Pay the re-delivery
  // fee", "Pay the outstanding bill". A stray verb after the noun ("Pay
  // the bill later") still matches — the noun is the demand.
  RegExp(r'\bpay\s+(?:[a-z][a-z-]*[\s,]+|rs\.?\s*[\d,.]+[\s,]+|'
          r'₹\s*[\d,.]+[\s,]+|\d[\d,.]*[\s,]+){0,4}'
          r'(?:fine|penalty|bail|charge|fee|tax|amount|deposit|dues|'
          r'bill|postage|rent|premium)\b',
      caseSensitive: false),
  // "Put Rs.10,000 into our FX plan" — the transfer verb differs from
  // pay/send/transfer but is still an instruction to move money.
  RegExp(r'\b(?:put|deposit)\s+(?:rs\.?|₹)\s*\d[\d,]*', caseSensitive: false),
  // "needs payment" / "needs a small deposit to stay active"
  RegExp(r'\bneeds?\s+(?:a\s+small\s+)?'
      r'(?:payment|deposit|advance|fee|charge)s?\b', caseSensitive: false),
  // "pay to start / register / release / withdraw ..."
  RegExp(r'\bpay\b.{0,25}\bto\s+'
      r'(?:start|register|join|begin|release|unlock|clear|remove|verify|'
      r'receive|keep|secure|withdraw|activate|complete|earn)\b',
      caseSensitive: false),
  RegExp(r'\bvia\s+upi\b', caseSensitive: false),
  RegExp(r'\btransfer\s+(?:rs\.?|₹)\s*\d[\d,]*', caseSensitive: false),
  // An unsolicited "invest Rs.X / invest in ..." IS a demand for money.
  RegExp(r'\binvest(?:ment)?\b', caseSensitive: false),
  // "requires immediate payment" / "pay to be removed from the list".
  RegExp(r'\brequire[sd]?\s+(?:an?\s+|immediate\s+)?'
      r'(?:payment|deposit|fee|charge)s?\b', caseSensitive: false),
  RegExp(r'\bpay\b.{0,20}\bto\s+be\s+'
      r'(?:removed|cleared|released|deleted|lifted|unblocked)\b',
      caseSensitive: false),
];

/// "Your UPI payment failed, scan again to retry" is an instruction to
/// re-initiate a payment (fires). "Your UPI payment was successful /
/// Rs.499 debited" is a transaction STATUS every bank sends (never fires).
/// Handled apart from [_paymentRes] so the status guard can look at what
/// follows the match without suppressing a genuine demand elsewhere in the
/// same message.
final _upiActionRe =
    RegExp(r'\bupi\b.{0,20}(pay|send|id)', caseSensitive: false);
final _upiStatusRe = RegExp(
    r'\b(?:successful|success|completed|debited|credited|received|'
    r'initiated|transaction\s+(?:id|no|number))\b',
    caseSensitive: false);
/// Action verbs that prove the message is a demand, not a status line.
final _upiAskRe = RegExp(
    r'\b(share|enter|send|pay|scan|click|verify|confirm|reply|type|'
    r'provide|give|upload|whatsapp|telegram)\b',
    caseSensitive: false);

List<SignalMatch> detectPaymentPull(String text) {
  final out = <SignalMatch>[];
  for (final m in _all(_upiRe, text)) {
    if (_isAdvisoryBefore(text, m.start)) continue;
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
  final scan = _withoutUrls(text);
  for (final re in _paymentRes) {
    for (final m in _all(re, scan)) {
      // "Do not pay any fee to claim a prize" is advice, not a demand.
      if (_isAdvisoryBefore(scan, m.start)) continue;
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
  // UPI action phrasing, guarded against transaction-status wording.
  for (final m in _all(_upiActionRe, scan)) {
    if (_isAdvisoryBefore(scan, m.start)) continue;
    final after = scan.substring(
        m.start, (m.end + 30).clamp(0, scan.length));
    // A status word only cancels the demand when nothing in the local
    // window ASKS for an action: "Share your UPI ID to get it credited"
    // contains "credited" but is still a demand, while "UPI payment was
    // successful, Rs.499 debited" is a bank notification.
    final window = scan.substring(
        (m.start - 48).clamp(0, scan.length), (m.end + 30).clamp(0, scan.length));
    final asks = _upiAskRe.hasMatch(window);
    if (!asks && _upiStatusRe.hasMatch(after)) continue;
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
  // 1800-toll-free (with or without separators) · Indian STD landline
  // (011-23456789 / 080 12345678) · 5+5 mobile · bare 10-digit mobile.
  r'(?:\+91[\s-]?)?(?:1800[\s-]?\d{3,4}[\s-]?\d{3,4}'
  r'|0\d{2,3}[\s-]?\d{6,8}|\d{5}[\s-]?\d{5}|\d{10})',
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

// ---------------------------------------------------------------------------
// REMOTE_ACCESS — screen-share / remote-control tooling + coercion
// ---------------------------------------------------------------------------

final _remoteRes = <RegExp>[
  RegExp(r'\banydesk\b', caseSensitive: false),
  RegExp(r'\bteamviewer\b', caseSensitive: false),
  RegExp(r'\brustdesk\b', caseSensitive: false),
  RegExp(r'\bquicksupport\b', caseSensitive: false),
  RegExp(r'screen\s*shar(e|ing)', caseSensitive: false),
  // "share your device screen", "share the phone screen"
  RegExp(r'share\s+(?:your\s+|the\s+)?(?:\w+\s+){0,2}screen',
      caseSensitive: false),
  RegExp(r'remote\s*(?:access|control|support|desktop|session|viewing|view)',
      caseSensitive: false),
  RegExp(r'share\s+(?:your\s+)?display', caseSensitive: false),
  RegExp(r'(install|download).{0,20}\bapk\b|\bapk\b.{0,20}(install|download)',
      caseSensitive: false),
];

List<SignalMatch> detectRemoteAccess(String text) {
  final out = <SignalMatch>[];
  final scan = _withoutUrls(text);
  for (final re in _remoteRes) {
    for (final m in _all(re, scan)) {
      // "If someone asks you to share your screen, it is likely a scam"
      // is advice ABOUT the trap, not the trap itself.
      if (_isAdvisoryBefore(scan, m.start)) continue;
      out.add(_m(
        id: 'REMOTE_ACCESS',
        label: 'Remote-access / screen-share trap',
        weight: RuleWeights.remoteAccess,
        source: text,
        start: m.start,
        end: m.end,
        detail: 'remote:${text.substring(m.start, m.end)}',
      ));
    }
  }
  _dedupe(out);
  return out;
}

// ---------------------------------------------------------------------------
// JOB_LURE — part-time / task / earn-per-day recruitment fraud
// ---------------------------------------------------------------------------

final _jobRes = <RegExp>[
  RegExp(r'part[\s-]?time', caseSensitive: false),
  RegExp(r'\bearn\b.{0,20}(rs\.?|₹|per day|/|daily)', caseSensitive: false),
  RegExp(r'\btask(?:s)?\b.{0,25}'
      r'(commission|reward|pay|bonus|earn|daily|earning)', caseSensitive: false),
  RegExp(r'(commission|reward)\s+per\s+task', caseSensitive: false),
  RegExp(r'\btelegram\b', caseSensitive: false),
  RegExp(r'\bdata\s+entry\b', caseSensitive: false),
  RegExp(r'\bwork\s+from\s+home\b', caseSensitive: false),
  RegExp(r'\bregistration\s+(?:fee|charges?)\b', caseSensitive: false),
  RegExp(r'\bpay\b.{0,25}\bto\s+(?:start|register|join|begin|earn)\b',
      caseSensitive: false),
  _jobRoleRe,
  // "job" as recruitment — never "job card" (a government document).
  RegExp(r'\bjobs?\b(?!\s+card\b)', caseSensitive: false),
];

/// Weak role words ("freelance", "typing", "surveys") only count when the
/// message ALSO carries recruitment language. "Your freelance project
/// payment has been processed" is payroll news, not a job lure.
final _jobRoleRe = RegExp(
    r'\b(?:freelance|typing|tutoring|surveys?|blog\s+writing|'
    r'resume\s+writing|product\s+testing|package\s+forwarding|'
    r'content\s+moderation|social\s+media\s+(?:manager|marketing|tasks?))\b',
    caseSensitive: false);

final _jobContext = RegExp(
    r'\bjobs?\b|\bworks?\b|\bearn|\btasks?\b|hiring|vacancy|vacancies|'
    r'apply|part[\s-]?time|from\s+home|per\s+(?:day|task|hour|post|article)|'
    r'commission|register|salary|recruit|\bpay\b|\bjoin\b',
    caseSensitive: false);

List<SignalMatch> detectJobLure(String text) {
  final out = <SignalMatch>[];
  final scan =
      _maskRanges(text, [..._all(_urlRe, text), ..._all(_upiRe, text)]);
  for (final re in _jobRes) {
    for (final m in _all(re, scan)) {
      if (identical(re, _jobRoleRe) && !_jobContext.hasMatch(scan)) continue;
      out.add(_m(
        id: 'JOB_LURE',
        label: 'Fake job / task lure',
        weight: RuleWeights.jobLure,
        source: text,
        start: m.start,
        end: m.end,
        detail: 'job:${text.substring(m.start, m.end)}',
      ));
    }
  }
  _dedupe(out);
  return out;
}

// ---------------------------------------------------------------------------
// DIGITAL_ARREST — fake law-enforcement video-call extortion
// ---------------------------------------------------------------------------

final _arrestRes = <RegExp>[
  RegExp(r'digital\s+arrest', caseSensitive: false),
  RegExp(r'video\s*call.{0,50}(police|cbi|officer|customs|court|verify)',
      caseSensitive: false),
  RegExp(r'(police|cbi|customs|officer|court).{0,50}video\s*call',
      caseSensitive: false),
  RegExp(r'money\s+laundering', caseSensitive: false),
  RegExp(r'(parcel|package|courier).{0,50}(drug|narcotic)',
      caseSensitive: false),
  RegExp(r'(drug|narcotic).{0,50}(parcel|package)', caseSensitive: false),
  // Law-enforcement / court language the short phrases above miss.
  // NOTE: "share your bank details" is a credential ask (SECRET_REQUEST),
  // never a law-enforcement threat — it must not be duplicated here.
  RegExp(r'\barrest\s+warrant\b', caseSensitive: false),
  RegExp(r'\b(?:police|cbi|ed)\s+complaint\b', caseSensitive: false),
  RegExp(r'\bunder\s+investigation\b', caseSensitive: false),
  RegExp(r'\b(?:cbi|police|cyber\s*crime|ed)\s+(?:investigation|probe|case)\b',
      caseSensitive: false),
  RegExp(r'\bcriminal\s+list\b', caseSensitive: false),
  RegExp(r'\bwatch\s*list\b', caseSensitive: false),
  RegExp(r'linked\s+to\s+(?:a\s+)?'
      r'(?:crime|crimina|fraud|fraudulent|illegal)', caseSensitive: false),
  RegExp(r'\b(?:face|facing)\s+(?:an\s+)?(?:arrest|charges|action)\b',
      caseSensitive: false),
  RegExp(r'wanted\s+by\s+(?:the\s+)?(?:police|cbi)', caseSensitive: false),
  RegExp(r'\bcustoms\s+seized\b|\bseized\s+(?:your\s+)?(?:parcel|package)\b',
      caseSensitive: false),
  RegExp(r'(?:income\s+tax|gst|police|cbi)\s+notice', caseSensitive: false),
  RegExp(r'\bcybercrime\b', caseSensitive: false),
  RegExp(r'police\s+(?:have\s+|has\s+)?(?:issued|registered|filed|arrested)',
      caseSensitive: false),
];

/// Aadhaar is an ID document, not a threat. DIGITAL_ARREST may only use it
/// when the SAME message also carries law-enforcement / fraud language —
/// "Aadhaar seeding updated" (genuine) must stay clean, "Aadhaar linked to
/// a crime" (extortion) must fire.
final _aadhaarRe = RegExp(r'\baadhaar\b', caseSensitive: false);

final _arrestContext = RegExp(
    r'crime|crimina|fraud|arrest|police|cbi|investigat|warrant|notice|'
    r'customs|court|laundering|watch\s*list|illegal|narcotic|offence|offense',
    caseSensitive: false);

List<SignalMatch> detectDigitalArrest(String text) {
  final out = <SignalMatch>[];
  final scan = _withoutUrls(text);
  final contextOk = _arrestContext.hasMatch(scan);
  void collect(RegExp re) {
    for (final m in _all(re, scan)) {
      out.add(_m(
        id: 'DIGITAL_ARREST',
        label: 'Digital-arrest style threat',
        weight: RuleWeights.digitalArrest,
        source: text,
        start: m.start,
        end: m.end,
        detail: 'arrest:${text.substring(m.start, m.end)}',
      ));
    }
  }

  for (final re in _arrestRes) {
    collect(re);
  }
  // Aadhaar alone is never a threat marker — needs the context above.
  if (contextOk) collect(_aadhaarRe);
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
