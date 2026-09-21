import 'package:flutter/material.dart';
import '../analysis/stages.dart';
import '../data/demo_scenarios.dart';
import '../models/verdict.dart';
import 'widgets/risk_widgets.dart';

/// Multi-stage attack-chain view: bait → link → harvest → OTP → fee,
/// each stage analyzed by the real engine with its own evidence.
class TimelineScreen extends StatefulWidget {
  const TimelineScreen({super.key});
  @override
  State<TimelineScreen> createState() => _TimelineScreenState();
}

class _TimelineScreenState extends State<TimelineScreen> {
  late final AttackChain _chain = buildChain(kycChainStages);

  @override
  Widget build(BuildContext context) {
    final chain = _chain;
    return Scaffold(
      appBar: AppBar(title: const Text('Attack chain')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: riskBg(chain.verdict, context),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(children: [
              Icon(riskIcon(chain.verdict),
                  color: riskColor(chain.verdict, context),
                  size: 40),
              const SizedBox(width: 12),
              Expanded(
                  child: Column(
                      crossAxisAlignment:
                          CrossAxisAlignment.start,
                      children: [
                    Text(
                        chain.isChain
                            ? '🚨 MULTI-STAGE SCAM DETECTED'
                            : 'No attack chain',
                        style: TextStyle(
                            color: riskColor(
                                chain.verdict, context),
                            fontSize: 18,
                            fontWeight: FontWeight.w800)),
                    Text(
                        '${chain.stagesFlagged}/${chain.stages.length} stages flagged · peak ${chain.maxScore}/100',
                        style: TextStyle(
                            color: riskColor(
                                chain.verdict, context))),
                  ])),
            ]),
          ),
          const SizedBox(height: 12),
          for (var i = 0; i < chain.stages.length; i++) ...[
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Column(children: [
                  Container(
                    width: 28,
                    height: 28,
                    decoration: BoxDecoration(
                      color: riskColor(
                          chain.stages[i].verdict, context),
                      shape: BoxShape.circle,
                    ),
                    child: Center(
                        child: Text('${i + 1}',
                            style: const TextStyle(
                                color: Colors.white,
                                fontWeight: FontWeight.w800))),
                  ),
                  if (i < chain.stages.length - 1)
                    Container(
                        width: 3,
                        height: 28,
                        color: riskColor(
                                chain.stages[i].verdict,
                                context)
                            .withValues(alpha: 0.4)),
                ]),
                const SizedBox(width: 10),
                Expanded(
                  child: Card(
                    child: ExpansionTile(
                      title: Text(chain.stages[i].title,
                          style: const TextStyle(
                              fontWeight: FontWeight.w700)),
                      subtitle: Text(
                          '${chain.stages[i].verdict.label} · ${chain.stages[i].score}/100'),
                      children: [
                        Padding(
                          padding: const EdgeInsets.all(12),
                          child: Column(
                            crossAxisAlignment:
                                CrossAxisAlignment.start,
                            children: [
                              Text(chain.stages[i].text,
                                  style: const TextStyle(
                                      fontStyle:
                                          FontStyle.italic)),
                              const SizedBox(height: 6),
                              Wrap(
                                spacing: 6,
                                children: chain
                                    .stages[i].signals
                                    .map((s) => s.id)
                                    .toSet()
                                    .map((id) => Chip(
                                        label: Text(id),
                                        visualDensity:
                                            VisualDensity
                                                .compact))
                                    .toList(),
                              ),
                              if (chain.stages[i].signals
                                  .isEmpty)
                                const Text(
                                    'No signals in this stage.',
                                    style: TextStyle(
                                        color: Colors.grey)),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ],
          const SizedBox(height: 8),
          const Text(
            'KYC bait → phishing → credential harvesting → OTP theft → payment fraud. Each stage keeps its own evidence above.',
            style: TextStyle(fontSize: 12, color: Colors.grey),
          ),
        ],
      ),
    );
  }
}
