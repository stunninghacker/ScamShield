import 'package:flutter/material.dart';
import '../models/scan_result.dart';
import 'widgets/highlighted_text.dart';

class ResultScreen extends StatelessWidget {
  final ScanResult result;
  const ResultScreen({super.key, required this.result});

  (Color, Color, IconData, String) _verdictStyle() {
    switch (result.verdict) {
      case Verdict.dangerous:
        return (const Color(0xFFB71C1C), const Color(0xFFFFEBEE),
            Icons.dangerous_outlined, 'Likely a scam');
      case Verdict.suspicious:
        return (const Color(0xFFE65100), const Color(0xFFFFF3E0),
            Icons.warning_amber_outlined, 'Looks suspicious');
      case Verdict.safe:
        return (const Color(0xFF1B5E20), const Color(0xFFE8F5E9),
            Icons.verified_outlined, 'Looks genuine');
    }
  }

  @override
  Widget build(BuildContext context) {
    final (fg, bg, icon, label) = _verdictStyle();
    return Scaffold(
      appBar: AppBar(title: const Text('Result — on-device')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
                color: bg, borderRadius: BorderRadius.circular(12)),
            child: Row(
              children: [
                Icon(icon, color: fg, size: 40),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(label,
                          style: TextStyle(
                              color: fg,
                              fontSize: 22,
                              fontWeight: FontWeight.w800)),
                      Text('Score ${result.score}/100 • '
                          '${result.signals.length} signal(s) • '
                          '${result.llmUsed ? "Gemma on-device" : "built-in explainer"}',
                          style: TextStyle(color: fg)),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          Text('Message (suspicious parts highlighted)',
              style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 6),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: HighlightedText(
                  source: result.sourceText, signals: result.signals),
            ),
          ),
          if (result.signals.isNotEmpty) ...[
            const SizedBox(height: 8),
            Wrap(
              spacing: 6,
              children: result.signals
                  .map((s) => s.id)
                  .toSet()
                  .map((id) => Chip(label: Text(id), visualDensity: VisualDensity.compact))
                  .toList(),
            ),
          ],
          const SizedBox(height: 16),
          Text('Why this verdict', style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 6),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Text(result.explanation,
                  style: const TextStyle(fontSize: 15, height: 1.5)),
            ),
          ),
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              border: Border.all(color: fg),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.checklist_outlined, color: fg),
                const SizedBox(width: 8),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('What to do',
                          style: TextStyle(
                              fontWeight: FontWeight.w700, color: fg)),
                      Text(result.whatToDo,
                          style: const TextStyle(fontSize: 14, height: 1.4)),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          const Text(
            'Checked fully offline. Nothing left your phone.',
            style: TextStyle(fontSize: 12, color: Colors.grey),
          ),
        ],
      ),
    );
  }
}
