import 'package:flutter/material.dart';
import '../data/demo_scenarios.dart';
import 'radar_screen.dart';
import 'scan_actions.dart';
import 'timeline_screen.dart';

/// Hackathon Demo Mode: 6 scenarios + bonus chain, one tap each.
class DemoScreen extends StatelessWidget {
  const DemoScreen({super.key});

  Future<void> _run(BuildContext context, DemoScenario s) async {
    switch (s.kind) {
      case ScenarioKind.single:
        await runTextScan(context, s.text ?? '',
            source: 'text', demo: true, staged: true);
        break;
      case ScenarioKind.radar:
        await Navigator.of(context).push(
            MaterialPageRoute(builder: (_) => const RadarScreen()));
        break;
      case ScenarioKind.timeline:
        await Navigator.of(context).push(MaterialPageRoute(
            builder: (_) => const TimelineScreen()));
        break;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Demo Mode')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const Card(
              child: ListTile(
                  leading: Icon(Icons.science_outlined),
                  title: Text(
                      'Six scenarios, preloaded. Airplane mode welcome.'),
                  subtitle: Text(
                      'Singles animate input → signals → risk → action. Radar streams a simulated call.'))),
          for (final s in demoScenarios)
            Card(
              child: ListTile(
                leading: Icon(
                    s.kind == ScenarioKind.radar
                        ? Icons.radar_outlined
                        : s.kind == ScenarioKind.timeline
                            ? Icons.timeline_outlined
                            : Icons.message_outlined),
                title: Text(s.title,
                    style:
                        const TextStyle(fontWeight: FontWeight.w700)),
                subtitle: Text(
                    '${s.subtitle} · expects ${s.expected}'),
                trailing: FilledButton(
                    onPressed: () => _run(context, s),
                    child: const Text('Run')),
                onTap: () => _run(context, s),
              ),
            ),
        ],
      ),
    );
  }
}
