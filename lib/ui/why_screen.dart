import 'dart:convert';
import 'package:flutter/material.dart';
import '../analysis/attack_chain.dart';
import '../analysis/explainer_copy.dart';
import '../analysis/scan_pipeline.dart';
import '../models/verdict.dart';
import 'widgets/risk_widgets.dart';

/// "Why this verdict?" — the evidence explainer screen.
///
/// Rules this screen follows:
///  - default view: plain words only, every claim traces to a fired signal;
///  - evidence (quoted message spans) and generated explanation are in
///    separately labeled sections, never mixed;
///  - nothing invented: empty scans say so plainly;
///  - technical detail (ids, offsets, weights, JSON) hides behind one
///    expandable section for judges;
///  - meaning never travels by color alone (icon + word + number);
///  - body text 14sp+, high-contrast theme colors.
class WhyScreen extends StatelessWidget {
  final PipelineResult result;
  const WhyScreen({super.key, required this.result});

  @override
  Widget build(BuildContext context) {
    final r = result;
    final c = riskColor(r.verdict, context);
    final textTheme = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Why this verdict?')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // 1 · Risk level at top: icon + word + family + score.
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(riskIcon(r.verdict), color: c, size: 40),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment:
                              CrossAxisAlignment.start,
                          children: [
                            Text(
                                r.verdict == Verdict.dangerous
                                    ? 'HIGH RISK'
                                    : r.verdict == Verdict.suspicious
                                        ? 'MEDIUM RISK'
                                        : 'LOW RISK',
                                style: textTheme.headlineSmall
                                    ?.copyWith(
                                        color: c,
                                        fontWeight:
                                            FontWeight.w800)),
                            Text('Scam type: ${r.family.label}',
                                style: textTheme.titleMedium),
                          ],
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Text(
                      'Risk score: ${r.score} out of 100',
                      style: textTheme.titleMedium
                          ?.copyWith(fontWeight: FontWeight.w700)),
                  const SizedBox(height: 6),
                  ScoreBar(score: r.score, verdict: r.verdict),
                  const SizedBox(height: 8),
                  Text(
                    r.confidence > 0
                        ? 'Our certainty: ${r.confidence.toStringAsFixed(2)} out of 1 '
                            '(an estimate — never perfect).'
                        : 'Our certainty: none — nothing risky was found.',
                    style: textTheme.bodyMedium,
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          // 2 · Evidence: exact words, in attack order.
          Text('WHAT WE FOUND — exact words from the message',
              style: textTheme.titleSmall),
          const SizedBox(height: 8),
          if (r.chain.steps.isEmpty)
            const Card(
                child: ListTile(
                    leading: Icon(Icons.check_circle_outline),
                    title: Text(
                        'Nothing risky in these words — no hidden link, '
                        'no secret-code request, no rush, no payment demand. '
                        'That is why the risk is low.',
                        style: TextStyle(fontSize: 14)))),
          for (var i = 0; i < r.chain.steps.length; i++)
            _EvidenceStep(
                index: i,
                last: i == r.chain.steps.length - 1,
                step: r.chain.steps[i]),
          const SizedBox(height: 16),
          // 3 · Generated explanation, clearly separated from evidence.
          Text('WHAT OUR HELPER SAYS — generated explanation',
              style: textTheme.titleSmall),
          const SizedBox(height: 8),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(r.explanation,
                      style: const TextStyle(fontSize: 14, height: 1.5)),
                  const SizedBox(height: 8),
                  Text(
                    r.llmUsed
                        ? 'Written by the on-device AI using only the evidence above. '
                            'The wording is generated; the facts are not.'
                        : 'Written by the built-in explainer from the evidence above '
                            '(AI model not installed). No new facts were added.',
                    style: textTheme.bodyMedium?.copyWith(
                        fontStyle: FontStyle.italic),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          // 4 · Recommended actions.
          Text('WHAT TO DO NOW',
              style: textTheme.titleSmall),
          const SizedBox(height: 8),
          for (var i = 0;
                  i < recommendedActions(r.verdict).length;
                  i++)
            Card(
              child: ListTile(
                leading: CircleAvatar(child: Text('${i + 1}')),
                title: Text(recommendedActions(r.verdict)[i],
                    style: const TextStyle(fontSize: 14)),
              ),
            ),
          Card(
            child: ListTile(
              leading: const Icon(Icons.lightbulb_outline),
              title: Text('Tip for ${r.family.label}: '
                  '${familyAdvice[r.family] ?? ''}',
                  style: const TextStyle(fontSize: 14)),
            ),
          ),
          const SizedBox(height: 8),
          // 5 · Judge details, expandable.
          ExpansionTile(
            leading: const Icon(Icons.engineering_outlined),
            title: const Text('For judges — technical details',
                style: TextStyle(fontSize: 14)),
            children: [
              _TechTable(result: r),
            ],
          ),
        ],
      ),
    );
  }
}

/// One evidence step on the attack rail: numbered node, stage + plain
/// title, verbatim quoted spans, plain why, points + strength.
class _EvidenceStep extends StatelessWidget {
  final int index;
  final bool last;
  final ChainStep step;
  const _EvidenceStep(
      {required this.index, required this.last, required this.step});

  @override
  Widget build(BuildContext context) {
    final d = step.signal;
    final textTheme = Theme.of(context).textTheme;
    return IntrinsicHeight(
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Column(
            children: [
              CircleAvatar(
                  radius: 14, child: Text('${index + 1}')),
              if (!last)
                const Expanded(
                    child: SizedBox(
                        width: 2,
                        child: ColoredBox(
                            color: Colors.grey))),
            ],
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Card(
              margin: const EdgeInsets.only(bottom: 12),
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('${step.stage} — '
                        '${plainSignalTitle[d.id] ?? d.label}',
                        style: textTheme.titleMedium?.copyWith(
                            fontWeight: FontWeight.w700)),
                    const SizedBox(height: 6),
                    Wrap(
                      spacing: 6,
                      runSpacing: 6,
                      children: [
                        for (final e in d.evidence)
                          Chip(
                              label: Text('“$e”',
                                  style: const TextStyle(
                                      fontSize: 14,
                                      fontWeight:
                                          FontWeight.w600)),
                              visualDensity:
                                  VisualDensity.compact),
                      ],
                    ),
                    const SizedBox(height: 6),
                    Text(plainSignalWhy[d.id] ?? '',
                        style:
                            const TextStyle(fontSize: 14, height: 1.4)),
                    const SizedBox(height: 6),
                    Text(
                        '+${d.contribution} points · '
                        '${strengthWord(d.strength)} '
                        '(${d.strength.toStringAsFixed(2)})',
                        style: textTheme.bodyMedium?.copyWith(
                            fontWeight: FontWeight.w700)),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// Judge table: every number traceable, plus the raw chain JSON.
class _TechTable extends StatelessWidget {
  final PipelineResult result;
  const _TechTable({required this.result});

  @override
  Widget build(BuildContext context) {
    final r = result;
    Widget row(String k, String v) => Padding(
          padding:
              const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(
                  width: 128,
                  child: Text(k,
                      style: const TextStyle(
                          fontWeight: FontWeight.w700,
                          fontSize: 13))),
              Expanded(
                  child: SelectableText(v,
                      style: const TextStyle(fontSize: 13))),
            ],
          ),
        );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        row('verdict', r.verdict.name),
        row('family', r.family.name),
        row('score', '${r.score}/100'),
        row('confidence', r.confidence.toStringAsFixed(2)),
        row('signals', r.signals.map((s) => s.id).join(', ')),
        for (final s in r.chain.steps)
          row(
              s.signal.id,
              '+${s.signal.contribution} · strength '
              '${s.signal.strength.toStringAsFixed(2)} · '
              'span ${s.signal.start}–${s.signal.end}'),
        row('engine', '${r.latencyMs} ms'),
        row('explainer', '${r.aiMs} ms · '
            '${r.llmUsed ? 'local-model' : 'built-in'}'),
        row('event', r.eventId.isEmpty ? '(none)' : r.eventId),
        Padding(
          padding: const EdgeInsets.all(16),
          child: SelectableText(
            const JsonEncoder.withIndent('  ')
                .convert(r.chain.toJson()),
            style: const TextStyle(
                fontSize: 12, fontFamily: 'monospace'),
          ),
        ),
      ],
    );
  }
}
