import 'dart:io';
import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import '../analysis/qr_intel.dart';
import '../analysis/url_intel.dart';
import '../analysis/verdict_report.dart';
import '../events/threat_events.dart';
import '../models/verdict.dart';
import '../ocr/ocr_service.dart';
import 'scan_actions.dart';
import 'widgets/risk_widgets.dart';

/// ScamLens: camera-first scanner.
/// Tabs: QR camera (on-device barcode) · URL check · Photo → OCR.
class LensScreen extends StatelessWidget {
  const LensScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 3,
      child: Scaffold(
        appBar: AppBar(
          title: const Text('ScamLens'),
          bottom: const TabBar(tabs: [
            Tab(icon: Icon(Icons.qr_code_scanner), text: 'QR'),
            Tab(icon: Icon(Icons.link_outlined), text: 'URL'),
            Tab(icon: Icon(Icons.photo_camera_outlined), text: 'Photo'),
          ]),
        ),
        body: const TabBarView(
            children: [_QrTab(), _UrlTab(), _PhotoTab()]),
      ),
    );
  }
}

// ---------------------------------------------------------------- QR ---
class _QrTab extends StatefulWidget {
  const _QrTab();
  @override
  State<_QrTab> createState() => _QrTabState();
}

class _QrTabState extends State<_QrTab>
    with AutomaticKeepAliveClientMixin {
  final _controller = MobileScannerController();
  QrReport? _report;
  bool _busy = false;

  @override
  bool get wantKeepAlive => true;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _onCode(String raw) async {
    if (_busy) return;
    setState(() => _busy = true);
    await _controller.stop();
    final rep = analyzeQr(raw);
    // Log an indicator event (never the raw payload beyond preview).
    String risk = 'suspicious';
    int score = 50;
    String category = 'QR Scan';
    if (rep.kind == QrKind.upiPayment) {
      category = 'Payment Scam';
      if (rep.upiPayee == null) {
        risk = 'dangerous';
        score = 85;
      }
    } else if (rep.kind == QrKind.url && rep.urlReport != null) {
      final u = rep.urlReport!;
      risk = u.risk == 'high'
          ? 'dangerous'
          : u.risk == 'medium'
              ? 'suspicious'
              : 'safe';
      score = u.risk == 'high' ? 85 : u.risk == 'medium' ? 50 : 5;
      category = 'Phishing Link';
    } else if (rep.kind == QrKind.text ||
        rep.kind == QrKind.contact ||
        rep.kind == QrKind.wifi) {
      risk = 'safe';
      score = 5;
      category = 'QR Scan';
    }
    try {
      await EventLog().log(EventLog.fromScan(
        source: 'qr',
        category: category,
        risk: risk,
        score: score,
        confidence: confidenceFor(score,
            hasSignals: risk != 'safe'),
        signals: const [],
        fullText: raw,
      ));
    } catch (_) {
      // Event logging is best-effort; the QR result still shows.
    }
    if (!mounted) return;
    setState(() {
      _report = rep;
      _busy = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    if (_report != null) return _qrResult(context, _report!);
    return Column(
      children: [
        Expanded(
          child: MobileScanner(
            controller: _controller,
            onDetect: (cap) {
              final raw = cap.barcodes
                  .map((b) => b.rawValue)
                  .whereType<String>()
                  .firstOrNull;
              if (raw != null && raw.trim().isNotEmpty) {
                _onCode(raw);
              }
            },
            errorBuilder: (_, err) => Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.no_photography_outlined,
                        size: 48),
                    const SizedBox(height: 8),
                    Text(
                        'Camera unavailable (${err.errorCode.name}). ${err.errorDetails ?? ''}',
                        textAlign: TextAlign.center),
                    const Text(
                        'On a phone, allow camera access. You can still use the URL and Photo tabs.',
                        textAlign: TextAlign.center,
                        style:
                            TextStyle(fontSize: 12, color: Colors.grey)),
                  ],
                ),
              ),
            ),
          ),
        ),
        const Padding(
          padding: EdgeInsets.all(16),
          child: Text('Point at a QR — UPI, link, contact or Wi-Fi.',
              style: TextStyle(color: Colors.grey)),
        ),
      ],
    );
  }

  Widget _qrResult(BuildContext context, QrReport rep) {
    final danger = rep.kind == QrKind.upiPayment ||
        (rep.urlReport?.risk == 'high');
    final v = danger ? Verdict.dangerous : Verdict.suspicious;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
              color: riskBg(v, context),
              borderRadius: BorderRadius.circular(12)),
          child: Row(children: [
            Icon(riskIcon(v), color: riskColor(v, context), size: 40),
            const SizedBox(width: 12),
            Expanded(
                child: Column(
                    crossAxisAlignment:
                        CrossAxisAlignment.start,
                    children: [
                  Text(
                      rep.kind == QrKind.upiPayment
                          ? '⚠️ POTENTIAL PAYMENT SCAM'
                          : rep.kindLabel,
                      style: TextStyle(
                          color: riskColor(v, context),
                          fontSize: 19,
                          fontWeight: FontWeight.w800)),
                  RiskBadge(verdict: v, compact: true),
                ])),
          ]),
        ),
        const SizedBox(height: 12),
        Card(
            child: ListTile(
                title: const Text('Decoded payload'),
                subtitle: Text(rep.raw.length > 220
                    ? '${rep.raw.substring(0, 220)}…'
                    : rep.raw))),
        if (rep.upiPayee != null)
          Card(
              child: ListTile(
                  leading: const Icon(Icons.payments_outlined),
                  title: Text('Payee: ${rep.upiPayee}'),
                  subtitle: Text(
                      'Name: ${rep.upiName ?? '—'} · Amount: ${rep.upiAmount ?? '—'}'))),
        if (rep.urlReport != null) _UrlFindings(rep.urlReport!),
        Card(
            child: Padding(
                padding: const EdgeInsets.all(12),
                child: Text(rep.note,
                    style: const TextStyle(
                        fontSize: 15, height: 1.5)))),
        const SizedBox(height: 8),
        Row(children: [
          Expanded(
              child: FilledButton(
                  onPressed: () => setState(() {
                        _report = null;
                        _controller.start();
                      }),
                  child: const Text('Analyze again'))),
          const SizedBox(width: 8),
          Expanded(
              child: OutlinedButton(
                  onPressed: () {
                    if (rep.kind == QrKind.url) {
                      runTextScan(context,
                          'Scanned QR links to: ${rep.raw}',
                          source: 'qr');
                    } else {
                      ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(
                              content: Text(
                                  'Do not pay. Verify the recipient through the official app.')));
                    }
                  },
                  child: const Text('Verify'))),
        ]),
      ],
    );
  }
}

// --------------------------------------------------------------- URL ---
class _UrlTab extends StatefulWidget {
  const _UrlTab();
  @override
  State<_UrlTab> createState() => _UrlTabState();
}

class _UrlTabState extends State<_UrlTab>
    with AutomaticKeepAliveClientMixin {
  final _ctrl = TextEditingController();
  UrlReport? _rep;

  @override
  bool get wantKeepAlive => true;

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  void _go() {
    final input = _ctrl.text.trim();
    if (input.isEmpty) return;
    setState(() => _rep = analyzeUrl(input));
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        TextField(
          controller: _ctrl,
          decoration: const InputDecoration(
            border: OutlineInputBorder(),
            labelText: 'Paste a link',
            hintText: 'https://… or upi://pay?…',
          ),
          onSubmitted: (_) => _go(),
        ),
        const SizedBox(height: 10),
        FilledButton.icon(
            onPressed: _go,
            icon: const Icon(Icons.search_outlined),
            label: const Text('Analyze URL')),
        if (_rep != null) ...[
          const SizedBox(height: 12),
          _UrlReportCard(
              rep: _rep!,
              onFullScan: () => runTextScan(
                  context, 'Check this link: ${_rep!.input}',
                  source: 'url')),
        ],
      ],
    );
  }
}

class _UrlFindings extends StatelessWidget {
  final UrlReport rep;
  const _UrlFindings(this.rep);

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Host: ${rep.host}',
                style:
                    const TextStyle(fontWeight: FontWeight.w700)),
            Text(
                'Scheme: ${rep.scheme}${rep.isHttps ? ' (secure transport)' : ' (NOT secure)'} · TLD: .${rep.tld} · subdomains: ${rep.subdomainCount}'),
            const Divider(),
            for (final f in rep.findings)
              ListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  leading: const Icon(Icons.flag_outlined,
                      size: 20),
                  title: Text(f.label,
                      style: const TextStyle(fontSize: 14)),
                  subtitle: Text(f.detail,
                      style: const TextStyle(fontSize: 12))),
          ],
        ),
      ),
    );
  }
}

class _UrlReportCard extends StatelessWidget {
  final UrlReport rep;
  final VoidCallback onFullScan;
  const _UrlReportCard(
      {required this.rep, required this.onFullScan});

  @override
  Widget build(BuildContext context) {
    if (!rep.valid) {
      return const Card(
          child: ListTile(
              leading: Icon(Icons.error_outline),
              title: Text('Not a valid URL'),
              subtitle:
                  Text('Paste a full link starting with https://')));
    }
    final v = rep.risk == 'high'
        ? Verdict.dangerous
        : rep.risk == 'medium'
            ? Verdict.suspicious
            : Verdict.safe;
    return Column(
      children: [
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
              color: riskBg(v, context),
              borderRadius: BorderRadius.circular(12)),
          child: Row(children: [
            Icon(riskIcon(v),
                color: riskColor(v, context), size: 36),
            const SizedBox(width: 10),
            Expanded(
                child: Column(
                    crossAxisAlignment:
                        CrossAxisAlignment.start,
                    children: [
                  Text('${rep.risk.toUpperCase()} RISK',
                      style: TextStyle(
                          color: riskColor(v, context),
                          fontWeight: FontWeight.w800,
                          fontSize: 18)),
                  Text(rep.host,
                      style: const TextStyle(fontSize: 13)),
                ])),
          ]),
        ),
        const SizedBox(height: 8),
        _UrlFindings(rep),
        const Card(
            child: ListTile(
                dense: true,
                leading: Icon(Icons.cloud_off_outlined),
                title: Text(
                    'Reputation lookup unavailable (offline). Redirect chains are never followed.',
                    style: TextStyle(fontSize: 12)))),
        OutlinedButton.icon(
            onPressed: onFullScan,
            icon: const Icon(Icons.shield_outlined),
            label: const Text('Run full message scan')),
      ],
    );
  }
}

// ------------------------------------------------------------- PHOTO ---
class _PhotoTab extends StatefulWidget {
  const _PhotoTab();
  @override
  State<_PhotoTab> createState() => _PhotoTabState();
}

class _PhotoTabState extends State<_PhotoTab>
    with AutomaticKeepAliveClientMixin {
  final _picker = ImagePicker();
  bool _busy = false;

  @override
  bool get wantKeepAlive => true;

  Future<void> _pick(ImageSource src) async {
    if (_busy) return;
    setState(() => _busy = true);
    try {
      final f = await _picker.pickImage(source: src);
      if (f == null) return;
      String text;
      try {
        text =
            (await OcrService.instance.recognizeFile(File(f.path)))
                .text;
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(SnackBar(
              content: Text(
                  'OCR failed ($e). The OCR model may still be downloading — try the paste box instead.')));
        }
        return;
      }
      if (text.trim().isEmpty) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                  content:
                      Text('No text found in that photo.')));
        }
        return;
      }
      if (mounted) {
        await runTextScan(context, text, source: 'image');
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
            content: Text(
                'Camera/gallery unavailable: $e. Grant permission in Settings.')));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }
  @override
  Widget build(BuildContext context) {
    super.build(context);
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          const Icon(Icons.document_scanner_outlined, size: 64),
          const SizedBox(height: 8),
          const Text(
              'Photograph an SMS, notice or payment screen.\nText is read fully offline, then analyzed.',
              textAlign: TextAlign.center),
          const SizedBox(height: 16),
          if (_busy) const CircularProgressIndicator(),
          if (!_busy) ...[
            FilledButton.icon(
                onPressed: () => _pick(ImageSource.camera),
                icon: const Icon(Icons.photo_camera_outlined),
                label: const Text('Take photo')),
            const SizedBox(height: 8),
            OutlinedButton.icon(
                onPressed: () => _pick(ImageSource.gallery),
                icon: const Icon(Icons.photo_library_outlined),
                label: const Text('Choose from gallery')),
          ],
        ],
      ),
    );
  }
}
