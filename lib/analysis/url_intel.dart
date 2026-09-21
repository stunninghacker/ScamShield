/// URL Intelligence — offline, deterministic URL analyzer.
///
/// Extracts hostname/protocol/TLD/punycode/IP/shortener/brand/credential-path
/// signals WITHOUT fetching anything: the URL is never visited, never
/// resolved, never downloaded (SPEC §24: treat scanned URLs as untrusted).
/// Redirect chains and domain-age reputation are honestly reported as
/// unavailable offline (see [UrlReport.unavailable]).
library;

import '../rules/constants.dart';

final _schemeRe = RegExp(r'^([a-zA-Z][a-zA-Z0-9+.-]*)://');

class UrlFinding {
  final String label;
  final String detail;
  const UrlFinding(this.label, this.detail);
}

/// 'low' | 'medium' | 'high' | 'unknown' (unparseable input).
class UrlReport {
  final String input;
  final bool valid;
  final String scheme;
  final bool isHttps;
  final String host;
  final String tld;
  final int subdomainCount;
  final bool isIp;
  final bool isShortener;
  final bool isLookalike;
  final bool isPunycode;
  final bool excessiveSubdomains;
  final List<String> brandHits;
  final bool credentialPath;
  final bool upiScheme;
  final List<UrlFinding> findings;
  final String risk;

  /// Capabilities honestly unavailable in offline mode.
  static const unavailable = [
    'Redirect chain (would require fetching the URL — never done)',
    'Domain age / reputation (no reputation API configured)',
  ];

  const UrlReport({
    required this.input,
    required this.valid,
    this.scheme = '',
    this.isHttps = false,
    this.host = '',
    this.tld = '',
    this.subdomainCount = 0,
    this.isIp = false,
    this.isShortener = false,
    this.isLookalike = false,
    this.isPunycode = false,
    this.excessiveSubdomains = false,
    this.brandHits = const [],
    this.credentialPath = false,
    this.upiScheme = false,
    this.findings = const [],
    this.risk = 'unknown',
  });
}

String _stripPort(String host) {
  final c = host.indexOf(':');
  return c == -1 ? host : host.substring(0, c);
}

UrlReport analyzeUrl(String rawInput) {
  final input = rawInput.trim();
  if (input.isEmpty) {
    return const UrlReport(input: '', valid: false);
  }
  final schemeM = _schemeRe.firstMatch(input);
  final scheme = (schemeM?.group(1) ?? '').toLowerCase();
  final isUpi = scheme == 'upi';

  String host = '';
  String path = '';
  if (schemeM != null) {
    var rest = input.substring(schemeM.end);
    final slash = rest.indexOf('/');
    if (slash == -1) {
      host = rest;
    } else {
      host = rest.substring(0, slash);
      path = rest.substring(slash);
    }
    // strip userinfo
    final at = host.lastIndexOf('@');
    if (at != -1) host = host.substring(at + 1);
    host = _stripPort(host).toLowerCase();
    // strip brackets for IPv6 literals
    if (host.startsWith('[') && host.endsWith(']')) {
      host = host.substring(1, host.length - 1);
    }
  } else if (input.toLowerCase().startsWith('www.')) {
    final slash = input.indexOf('/');
    host = (slash == -1 ? input : input.substring(0, slash))
        .toLowerCase()
        .replaceFirst(RegExp(r'^www\.'), '');
    // keep www-stripped host for analysis
    host = _stripPort(host);
    if (slash != -1) path = input.substring(slash);
  } else {
    return UrlReport(input: input, valid: false);
  }
  if (host.isEmpty) return UrlReport(input: input, valid: false);

  final h = host.startsWith('www.') ? host.substring(4) : host;
  final parts = h.split('.');
  final tld = parts.length > 1 ? parts.last : '';
  final subCount = parts.length > 2 ? parts.length - 2 : 0;
  final isIp = RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(h) ||
      h.contains(':'); // IPv6 remnant
  final isShort = shortenerHosts.contains(h) ||
      shortenerHosts.any((s) => h == s || h.endsWith('.$s'));
  final isPuny = h.contains('xn--');
  final excessive = subCount >= 3;
  final brands = brandKeywords.where((b) => h.contains(b)).toList();
  final trusted = trustedHosts.contains(h) ||
      trustedHosts.any((t) => h == t || h.endsWith('.$t'));
  final lookalike = !trusted &&
      brands.isNotEmpty &&
      (suspiciousTlds.contains(tld) || h.contains('-') || !isUpi);
  final lowPath = path.toLowerCase();
  final credPath = RegExp(
          r'login|signin|verify|verification|kyc|otp|password|credential|account|bank|secure|update')
      .hasMatch(lowPath);

  final findings = <UrlFinding>[];
  void add(String l, String d) => findings.add(UrlFinding(l, d));
  if (scheme.isNotEmpty && scheme != 'https' && !isUpi) {
    add('Not HTTPS', 'Uses "$scheme" — login pages without HTTPS leak data.');
  }
  if (isIp) add('IP-address host', 'Real banks never use raw IP addresses.');
  if (isShort) {
    add('URL shortener', 'Shorteners hide the real destination.');
  }
  if (isPuny) {
    add('Punycode / lookalike characters',
        'Internationalized characters can impersonate real domains.');
  }
  if (lookalike) {
    add('Brand impersonation pattern',
        'Contains ${brands.join(', ')} but is not an official domain.');
  }
  if (suspiciousTlds.contains(tld)) {
    add('Suspicious TLD', '.$tld is heavily abused for phishing.');
  }
  if (excessive) {
    add('Excessive subdomains', '$subCount subdomains — mimics legit sites.');
  }
  if (credPath && !trusted) {
    add('Credential-collection path',
        'Path suggests login/KYC/password harvesting.');
  }
  if (isUpi) {
    add('UPI payment link',
        'Opens a payment request — confirm the payee before approving.');
  }
  if (findings.isEmpty && trusted) {
    add('Official domain', 'Matches a known official domain pattern.');
  }

  String risk;
  if (lookalike || (isIp && (brands.isNotEmpty || credPath))) {
    risk = 'high';
  } else if (findings.isNotEmpty &&
      !(findings.length == 1 && findings.first.label == 'Official domain')) {
    risk = 'medium';
  } else {
    risk = 'low';
  }

  return UrlReport(
    input: input,
    valid: true,
    scheme: scheme.isEmpty ? 'https' : scheme,
    isHttps: scheme == 'https',
    host: h,
    tld: tld,
    subdomainCount: subCount,
    isIp: isIp,
    isShortener: isShort,
    isLookalike: lookalike,
    isPunycode: isPuny,
    excessiveSubdomains: excessive,
    brandHits: brands,
    credentialPath: credPath,
    upiScheme: isUpi,
    findings: findings,
    risk: risk,
  );
}
