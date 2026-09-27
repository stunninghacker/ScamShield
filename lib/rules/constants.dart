/// ALL tuning lives here. Change weights/thresholds only in this file.
///
/// Scoring: sum of fired signal weights, clamped to 0..100,
/// floored at the SUSPICIOUS threshold when at least one pattern fired.
/// Verdict: score < suspiciousThreshold => SAFE,
///          score < dangerousThreshold => SUSPICIOUS,
///          else DANGEROUS.
///
/// Weight tiers (deliberate, documented):
///  - CRITICAL (60): a credential demand (SECRET), a remote-access
///    instruction (REMOTE), a coercive/digital-arrest threat
///    (DIGITAL_ARREST) and a money demand (PAYMENT). Each is blocking on
///    its own — that IS the attack, and no genuine message asks for it.
///  - TECHNIQUE (40): an urgency/threat, a lure, a recruitment lure.
///    Alone they only reach SUSPICIOUS (warn, don't block); combined with
///    any second cue (link 20 + threat 40 = 60) they block.
///  - SUPPORTING (15-20): a bare link, a callback number, brand
///    impersonation. They corroborate; they never block alone.
///
/// This mirrors the verdict rubric in test/eval_harness_test.dart, so a
/// label of DANGEROUS/SUSPICIOUS/SAFE can be checked against the engine
/// without circular reasoning.
///
/// Tuned so the 4 bundled demo samples land:
///   sample1 (KYC phishing)  -> DANGEROUS
///   sample2 (lottery lure)  -> DANGEROUS
///   sample3 (courier borderline) -> SUSPICIOUS (20+15+20 = 55)
///   sample4 (genuine alert) -> SAFE (score 0)
library;

class RuleWeights {
  // LINK_RISK breakdown (stackable per URL, capped by linkCap):
  static const int linkBase = 20; // any URL found
  static const int linkShortener = 15; // bit.ly, tinyurl, etc.
  static const int linkHttp = 10; // plain http:// (no TLS)
  static const int linkIpHost = 20; // http://192.168.x.x/... etc.
  static const int linkLookalike = 25; // bank name + wrong TLD / shady TLD
  static const int linkCap = 60; // max total from links (avoid one URL => 90)

  static const int secretRequest = 60; // OTP / PIN / CVV / password ... CRITICAL
  static const int urgencyThreat = 40; // blocked / 24 hours / last warning ...
  static const int rewardLure = 40; // won lottery / cashback / claim prize ...
  static const int paymentPull = 60; // UPI handle / pay ₹ / invest ... CRITICAL
  static const int callback = 15; // phone number + call-now language
  static const int impersonation = 20; // bank/govt/courier + any other signal
  static const int remoteAccess = 60; // AnyDesk / screen share CRITICAL
  static const int jobLure = 40; // part-time task / earn-per-day lure
  static const int digitalArrest = 60; // digital arrest / video-call CRITICAL

  // Spammy repeats of the same class count once extra (not N times):
  // each signal class contributes its weight once per scan, EXCEPT links
  // which sum per-URL up to linkCap. This keeps scoring predictable.
}

class RuleThresholds {
  static const int suspicious = 30; // score >= 30 => SUSPICIOUS
  static const int dangerous = 60; // score >= 60 => DANGEROUS
}

/// Shortener hosts (lowercase, no scheme).
const shortenerHosts = <String>{
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'cutt.ly',
  'rb.gy',
  'rebrand.ly',
  'shorturl.at',
  'tiny.cc',
};

/// Shady / abuse-prone TLDs that are rare for real Indian banks.
const suspiciousTlds = <String>{
  'xyz',
  'top',
  'click',
  'buzz',
  'work',
  'support',
  'verify',
  'online',
  'link',
  'info',
  'tk',
  'ml',
  'ga',
  'cf',
};

/// Brand keywords scammers borrow. If one of these appears INSIDE the URL
/// host but the host is not the brand's real domain, that's lookalike.
const brandKeywords = <String>{
  'sbi',
  'hdfc',
  'icici',
  'axis',
  'kotak',
  'pnb',
  'bob',
  'canara',
  'unionbank',
  'yesbank',
  'paytm',
  'phonepe',
  'upi',
  'rbi',
  'incometax',
  'kyc',
  'kbc',
};

/// Real domains that are NOT lookalike even if they contain a brand keyword.
/// Keep tiny on purpose: genuine alerts in the demo have NO link at all.
const trustedHosts = <String>{
  'sbi.co.in',
  'onlinesbi.com',
  'hdfcbank.com',
  'icicibank.com',
  'axisbank.com',
  'kotak.com',
  'pnb.co.in',
  'bankofbaroda.in',
  'canarabank.com',
  'unionbankofindia.co.in',
  'yesbank.in',
  'rbi.org.in',
  'incometax.gov.in',
  'paytm.com',
  'phonepe.com',
};
