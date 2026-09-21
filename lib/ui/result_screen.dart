import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../analysis/scan_pipeline.dart';
import '../analysis/verdict_report.dart';
import '../llm/prompt_template.dart';
import '../events/threat_events.dart';
import '../models/verdict.dart';
import '../settings/app_settings.dart';
import 'widgets/highlighted_text.dart';
import 'widgets/risk_widgets.dart';

/// Evidence-first result: verdict → why (weighted evidence) → action.
/// [staged] reveals sections progressively for Demo Mode drama.
class ResultScreen extends StatefulWidget {
  final PipelineResult result;
  final bool staged;
  const ResultScreen({super.key, required this.result, this.staged = false});

  @override
  State<ResultScreen> createState() => _ResultScreenState();
}

class _ResultScreenState extends State<ResultScreen> {
  int _stage = 99; // sections revealed so far when staged

  @override
  void initState() {
    super.initState();
    // Haptic punch scaled to risk (surprise, but trustworthy).
    switch (widget.result.verdict) {
      case Verdict.dangerous:
        HapticFeedback.heavyImpact();
        break;
      case Verdict.suspicious:
        HapticFeedback.mediumImpact();
        break;
      case Verdict.safe:
        HapticFeedback.lightImpact();
        break;
    }
    if (widget.staged) {
      _stage = 0;
      for (var i = 1; i <= 3; i++) {
        Future.delayed(Duration(milliseconds: 700 * i), () {
          if (mounted) setState(() => _stage = i);
        });
      }
      Future.delayed(const Duration(milliseconds: 2200), () {
        if (mounted) setState(() => _stage = 99);
      });
    }
  }

  Future<void> _action(String label, String detail) async {
    if (widget.result.eventId.isNotEmpty) {
      await EventLog().setAction(widget.result.eventId, label);
    }
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Marked as "$label". $detail')));
    setState(() {});
  }

  void _verifySheet() {
    showModalBottomSheet(
      context: context,
      builder: (_) => Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Verify safely',
                style: TextStyle(
                    fontSize: 18, fontWeight: FontWeight.w800)),
            const SizedBox(height: 8),
            const Text(
                '1. Open the official bank / courier app yourself — never the link above.\n'
                '2. Call the number printed on your card or the official site — never the callback number.\n'
                '3. Ask: "Did you contact me?" using an independently verified channel.'),
            const SizedBox(height: 12),
            FilledButton(
                onPressed: () {
                  Navigator.of(context).pop();
                  _action('Verify',
                      'Use only official apps and numbers.');
                },
                child: const Text('I understand')),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final r = widget.result;
    final c = riskColor(r.verdict, context);
    final bg = riskBg(r.verdict, context);
    final parts = contributionsFor(r.breakdown);
    final family = AppSettings.instance.familyMode;
    final staged = widget.staged;

    return Scaffold(
      appBar: AppBar(
        title: Text('${r.category} — on-device'),
        actions: [
          IconButton(
            tooltip: 'Copy report',
            icon: const Icon(Icons.copy_outlined),
            onPressed: () {
              final buf = StringBuffer()
                ..writeln('ScamShield risk score: ${r.score}/100 '
                    '(${r.verdict.riskWord} RISK)')
                ..writeln('Category: ${r.category}')
                ..writeln('Evidence:');
              for (final p in parts) {
                buf.writeln('+${p.weight} ${p.label}');
              }
              buf
                ..writeln('What to do: ${r.whatToDo}')
                ..writeln(
                    'Assessment only — cannot guarantee fraud.');
              Clipboard.setData(ClipboardData(text: buf.toString()));
              ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Report copied.')));
            },
          )
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // 1 · Verdict banner.
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
                color: bg, borderRadius: BorderRadius.circular(12)),
            child: Row(
              children: [
                Icon(riskIcon(r.verdict), color: c, size: 44),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                          r.verdict == Verdict.dangerous
                              ? '🚨 HIGH RISK'
                              : r.verdict == Verdict.suspicious
                                  ? '⚠️ MEDIUM RISK'
                                  : '✅ LOW RISK',
                          style: TextStyle(
                              color: c,
                              fontSize: 22,
                              fontWeight: FontWeight.w800)),
                      Text(r.verdict.label,
                          style: TextStyle(color: c, fontSize: 15)),
                      const SizedBox(height: 4),
                      Wrap(
                        spacing: 6,
                        runSpacing: 4,
                        children: [
                          RiskBadge(verdict: r.verdict, compact: true),
                          Chip(
                              label: Text(r.category),
                              visualDensity:
                                  VisualDensity.compact),
                          Chip(
                              label: Text(r.source),
                              visualDensity:
                                  VisualDensity.compact),
                        ],
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          ScoreBar(score: r.score, verdict: r.verdict),
          if (r.confidence > 0) ...[
            const SizedBox(height: 6),
            Text(
                'ASSESSMENT · Confidence ${(r.confidence).toStringAsFixed(2)} (heuristic) · '
                'engine ${r.latencyMs} ms · explained in ${r.aiMs} ms · '
                '${r.llmUsed ? 'Local Gemma on-device' : 'built-in explainer (model not bundled)'}',
                style:
                    const TextStyle(fontSize: 12, color: Colors.grey)),
          ],
          if (r.context.isNotEmpty) ...[
            const SizedBox(height: 8),
            Wrap(
              spacing: 6,
              runSpacing: 4,
              children: [
                const Chip(
                    label: Text('AI context (heuristic):'),
                    visualDensity: VisualDensity.compact),
                for (final t in r.context)
                  Chip(
                      label: Text(t),
                      visualDensity: VisualDensity.compact),
              ],
            ),
          ],
          // Family STOP card.
          if (family && r.verdict != Verdict.safe) ...[
            const SizedBox(height: 12),
            _FamilyStopCard(
                contact: AppSettings.instance.trustedContact),
          ],
          // 2 · Evidence.
          if (!staged || _stage >= 1) ...[
            const SizedBox(height: 16),
            Text('DETECTED — WHY WE FLAGGED THIS',
                style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 6),
            if (parts.isEmpty)
              const Card(
                  child: ListTile(
                      leading: Icon(Icons.check_circle_outline),
                      title: Text(
                          'No risky patterns found — no link, no secret request, no pressure.'))),
            for (final p in parts)
              Card(
                child: ListTile(
                  leading: const Icon(Icons.flag_outlined),
                  title: Text(p.label),
                  trailing: Text('+${p.weight}',
                      style: const TextStyle(
                          fontWeight: FontWeight.w800, fontSize: 16)),
                ),
              ),
            const SizedBox(height: 8),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: HighlightedText(
                    source: r.sourceText, signals: r.signals),
              ),
            ),
          ],
          // 3 · Explanation.
          if (!staged || _stage >= 2) ...[
            const SizedBox(height: 16),
            Text('What this means',
                style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 6),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Text(r.explanation,
                    style:
                        const TextStyle(fontSize: 15, height: 1.5)),
              ),
            ),
          ],
          // 4 · Action.
          if (!staged || _stage >= 3) ...[
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                border: Border.all(color: c),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(Icons.checklist_outlined, color: c),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Column(
                      crossAxisAlignment:
                          CrossAxisAlignment.start,
                      children: [
                        Text('RECOMMENDATION — What to do',
                            style: TextStyle(
                                fontWeight: FontWeight.w700,
                                color: c)),
                        Text(r.whatToDo,
                            style: const TextStyle(
                                fontSize: 14, height: 1.4)),
                        const SizedBox(height: 4),
                        Text(
                            'हिंदी (beta): ${PromptTemplate.hindiActionFor(r.verdict)}',
                            style: const TextStyle(
                                fontSize: 13,
                                height: 1.4,
                                color: Colors.grey)),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                    child: OutlinedButton.icon(
                        onPressed: _verifySheet,
                        icon: const Icon(Icons.verified_outlined),
                        label: const Text('Verify'))),
                const SizedBox(width: 8),
                Expanded(
                    child: OutlinedButton.icon(
                        onPressed: () => _action('Block',
                            'Blocked and logged locally.'),
                        icon: const Icon(Icons.block_outlined),
                        label: const Text('Block'))),
                const SizedBox(width: 8),
                Expanded(
                    child: OutlinedButton.icon(
                        onPressed: () => _action('Report',
                            'Report via your bank / 1930 helpline.'),
                        icon:
                            const Icon(Icons.report_outlined),
                        label: const Text('Report'))),
              ],
            ),
            const SizedBox(height: 8),
            const Text(
              'ScamShield provides a risk assessment and cannot guarantee that content is fraudulent.',
              style: TextStyle(fontSize: 12, color: Colors.grey),
            ),
          ],
        ],
      ),
    );
  }
}

class _FamilyStopCard extends StatelessWidget {
  final String contact;
  const _FamilyStopCard({required this.contact});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFFB71C1C),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('🛑 STOP',
              style: TextStyle(
                  color: Colors.white,
                  fontSize: 26,
                  fontWeight: FontWeight.w900)),
          const Text('Someone may be trying to trick you.',
              style: TextStyle(color: Colors.white, fontSize: 15)),
          const SizedBox(height: 8),
          const Text(
              'Do NOT:\n❌ Share OTP\n❌ Send money\n❌ Install unknown apps\n❌ Share your screen',
              style: TextStyle(color: Colors.white, height: 1.6)),
          const SizedBox(height: 8),
          const Text('Instead: verify using the official app.',
              style: TextStyle(
                  color: Colors.white, fontWeight: FontWeight.w700)),
          if (contact.isNotEmpty) ...[
            const SizedBox(height: 8),
            FilledButton.icon(
              style: FilledButton.styleFrom(
                  backgroundColor: Colors.white,
                  foregroundColor: const Color(0xFFB71C1C)),
              onPressed: () => Clipboard.setData(
                  ClipboardData(text: contact)),
              icon: const Icon(Icons.phone_outlined),
              label: Text('Trusted: $contact (tap to copy)'),
            ),
          ],
        ],
      ),
    );
  }
}
