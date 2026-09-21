import 'package:flutter/material.dart';
import '../events/threat_events.dart';

/// Honest privacy disclosure: exactly what runs where, what is stored,
/// and working delete switches. Cloud analysis has no backend configured,
/// so the toggle stays off and says so.
class PrivacyScreen extends StatefulWidget {
  const PrivacyScreen({super.key});
  @override
  State<PrivacyScreen> createState() => _PrivacyScreenState();
}

class _PrivacyScreenState extends State<PrivacyScreen> {
  Future<void> _clear() async {
    await EventLog().clear();
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
        content: Text(
            'Scam history and analysis data deleted from this phone.')));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Privacy Center')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text('Processing',
              style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 6),
          const Card(
              child: Column(children: [
            ListTile(
                leading: Icon(Icons.smartphone_outlined),
                title: Text('On-device'),
                subtitle: Text(
                    '✓ Rule engine\n✓ OCR & QR reading\n✓ Explanations (Gemma or built-in)\n✓ History & analytics')),
            Divider(height: 1),
            ListTile(
                leading: Icon(Icons.cloud_off_outlined),
                title: Text('Cloud'),
                subtitle: Text(
                    'No cloud backend is configured. Nothing is uploaded, ever.\n\n'
                    'ScamShield security analysis and fallback operate locally; '
                    'optional local Gemma inference is available only when the model asset is present.')),
            Divider(height: 1),
            ListTile(
                leading: Icon(Icons.policy_outlined),
                title: Text('Exact status'),
                subtitle: Text(
                    'NETWORK ACCESS\nNone\n\nExternal APIs\nNone\n\nURL fetching\nDisabled\n\nQR execution\nDisabled\n\nCLOUD AI\nNot configured\n\nLOCAL ANALYSIS\nActive')),
          ])),
          const SizedBox(height: 12),
          Text('What history stores',
              style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 6),
          const Card(
              child: ListTile(
                  subtitle: Text(
                      'Risk, category, score, signal list, evidence count, action taken, attack-chain links, and a redacted preview (account numbers and OTPs masked). Full messages and recordings are never stored.'))),
          const SizedBox(height: 12),
          FilledButton.icon(
              onPressed: _clear,
              icon: const Icon(Icons.delete_outline),
              label: const Text('Clear scam history')),
          const SizedBox(height: 8),
          OutlinedButton.icon(
              onPressed: _clear,
              icon: const Icon(Icons.folder_delete_outlined),
              label: const Text('Delete analysis data')),
          const SizedBox(height: 8),
          SwitchListTile(
            title: const Text('Cloud analysis'),
            subtitle: const Text(
                'Unavailable — no cloud backend configured. Local protection stays active.'),
            value: false,
            onChanged: (_) {
              ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                      content: Text(
                          'Cloud analysis is not available in this build.')));
            },
          ),
        ],
      ),
    );
  }
}
