import 'package:flutter/material.dart';
import '../analysis/scan_pipeline.dart';
import '../analysis/verdict_report.dart';
import '../data/demo_scenarios.dart';
import '../llm/gemma_service.dart';
import '../rules/constants.dart';

/// Judge Mode: technical depth without cluttering consumer UI.
class JudgeScreen extends StatelessWidget {
  const JudgeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final weights = {
      'LINK_RISK (base/cap)':
          '${RuleWeights.linkBase}/${RuleWeights.linkCap}',
      'SECRET_REQUEST': '${RuleWeights.secretRequest}',
      'URGENCY_THREAT': '${RuleWeights.urgencyThreat}',
      'REWARD_LURE': '${RuleWeights.rewardLure}',
      'PAYMENT_PULL': '${RuleWeights.paymentPull}',
      'CALLBACK': '${RuleWeights.callback}',
      'REMOTE_ACCESS': '${RuleWeights.remoteAccess}',
      'JOB_LURE': '${RuleWeights.jobLure}',
      'DIGITAL_ARREST': '${RuleWeights.digitalArrest}',
      'IMPERSONATION': '${RuleWeights.impersonation}',
    };
    return Scaffold(
      appBar: AppBar(title: const Text('Judge Mode')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _card(context, 'System architecture', const [
            'Layer 1 — deterministic rules (10 signals, owns verdict)',
            'Layer 2 — heuristic classifier (category from signals)',
            'Layer 3 — context (attack chains, radar transcripts)',
            'Layer 4 — risk engine (score + evidence + action)',
            'LLM explains only; sanitizer drops unfired claims',
          ]),
          _card(context, 'Model', [
            'flutter_gemma 0.9.0 (MediaPipe LLM Inference)',
            'gemma-3-1b-it.task (.task bundled by user)',
            'Status: ${GemmaService.instance.isReady ? 'READY on-device' : 'fallback (model file not placed)'}',
            'Temp 0.2 · topK 1 · grounded prompt + fallback',
          ]),
          _card(context, 'Latency', [
            'Last engine pass: ${ScanPipeline.instance.lastLatencyMs} ms (on-device rules)',
            'LLM explanation: up to ~30 s or instant fallback',
          ]),
          _card(context, 'Detection signals (id → weight)', [
            for (final e in weights.entries) '${e.key} → ${e.value}',
            'Thresholds: SAFE <${RuleThresholds.suspicious}, '
                'SUSPICIOUS <${RuleThresholds.dangerous}, else DANGEROUS',
          ]),
          _card(context, 'Signal labels', [
            for (final e in signalLabels.entries)
              '${e.key}: ${e.value}',
          ]),
          _card(context, 'APIs & sync', const [
            'External APIs: none configured (reputation: unavailable)',
            'WebSocket: none (Command Center reads the local event log)',
            'Phone↔desktop sync: user-initiated clipboard JSON export/import',
            'Permissions: camera (Lens), photos (OCR). No SMS reading, no internet.',
          ]),
          _card(context, 'Demo scenarios', [
            for (final s in demoScenarios)
              '${s.title} → expects ${s.expected}',
          ]),
          _card(context, 'Device', const [
            'Target: Android, minSdk 26',
            'Demo-proof: airplane mode ON, all features above stay live',
          ]),
        ],
      ),
    );
  }

  Widget _card(
      BuildContext context, String title, List<String> lines) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title,
                style: const TextStyle(
                    fontWeight: FontWeight.w800, fontSize: 15)),
            const SizedBox(height: 6),
            for (final l in lines)
              Padding(
                padding:
                    const EdgeInsets.symmetric(vertical: 1),
                child: Text('• $l',
                    style: const TextStyle(fontSize: 13)),
              ),
          ],
        ),
      ),
    );
  }
}
