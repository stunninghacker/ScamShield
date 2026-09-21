/// QR payload classifier — offline, deterministic.
///
/// Distinguishes URL / UPI-payment / contact / Wi-Fi / plain-text QR codes.
/// KEY DISTINCTION (SPEC §9): a UPI QR always *requests* money from the
/// scanner. Any QR presented as a way to "receive money / get a refund" that
/// decodes to a `upi://pay` request is the scam pattern itself — we flag it.
///
/// We never verify a transaction: classification only, no financial claims.
library;

import 'url_intel.dart';

enum QrKind { upiPayment, url, wifi, contact, text, invalid }

class QrReport {
  final QrKind kind;
  final String raw;
  final String? upiPayee;
  final String? upiName;
  final String? upiAmount;
  final UrlReport? urlReport;
  final String note;

  const QrReport({
    required this.kind,
    required this.raw,
    this.upiPayee,
    this.upiName,
    this.upiAmount,
    this.urlReport,
    required this.note,
  });

  String get kindLabel {
    switch (kind) {
      case QrKind.upiPayment:
        return 'UPI payment request';
      case QrKind.url:
        return 'Website link';
      case QrKind.wifi:
        return 'Wi-Fi credentials';
      case QrKind.contact:
        return 'Contact card';
      case QrKind.text:
        return 'Plain text';
      case QrKind.invalid:
        return 'Unreadable / empty';
    }
  }
}

QrReport analyzeQr(String rawInput) {
  final raw = rawInput.trim();
  if (raw.isEmpty) {
    return const QrReport(
        kind: QrKind.invalid, raw: '', note: 'QR was empty or unreadable.');
  }
  final low = raw.toLowerCase();

  // UPI payment request.
  if (low.startsWith('upi://pay')) {
    Uri? uri;
    try {
      uri = Uri.parse(raw);
    } catch (_) {
      uri = null;
    }
    final q = uri?.queryParameters ?? const {};
    final pa = q['pa'];
    final pn = q['pn'];
    final am = q['am'];
    final riskNote = (pa == null || pa.isEmpty)
        ? 'UPI request with no payee — highly suspicious.'
        : 'This QR ASKS YOU to pay'
            ' ${am != null && am.isNotEmpty ? '₹$am ' : ''}'
            'to "$pa"${pn != null && pn.isNotEmpty ? ' ($pn)' : ''}. '
            'Anyone saying "scan to RECEIVE money" is lying: '
            'scanning can only SEND.';
    return QrReport(
      kind: QrKind.upiPayment,
      raw: raw,
      upiPayee: pa,
      upiName: pn,
      upiAmount: am,
      note: riskNote,
    );
  }

  // Website link.
  if (low.startsWith('http://') ||
      low.startsWith('https://') ||
      low.startsWith('www.')) {
    final rep = analyzeUrl(raw);
    return QrReport(
      kind: QrKind.url,
      raw: raw,
      urlReport: rep,
      note: rep.risk == 'high'
          ? 'QR hides a high-risk link. Do not open it.'
          : rep.risk == 'medium'
              ? 'QR hides a link worth verifying before opening.'
              : 'QR contains a link with no obvious risk markers.',
    );
  }

  // Wi-Fi credentials.
  if (low.startsWith('wifi:')) {
    return QrReport(
      kind: QrKind.wifi,
      raw: raw,
      note: 'Joins a Wi-Fi network. Only scan on trusted premises — '
          'rogue hotspots can intercept traffic.',
    );
  }

  // Contact cards.
  if (low.startsWith('begin:vcard') || low.startsWith('mecard:')) {
    return QrReport(
      kind: QrKind.contact,
      raw: raw,
      note: 'Adds a contact. Harmless by itself — verify the details '
          'before calling back.',
    );
  }

  return QrReport(
    kind: QrKind.text,
    raw: raw.length > 200 ? '${raw.substring(0, 200)}…' : raw,
    note: 'Plain text with no payment or link action.',
  );
}
