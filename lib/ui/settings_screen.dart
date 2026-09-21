import 'package:flutter/material.dart';
import '../settings/app_settings.dart';
import 'command_screen.dart';
import 'demo_screen.dart';
import 'judge_screen.dart';
import 'privacy_screen.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});
  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  final _contactCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    _contactCtrl.text = AppSettings.instance.trustedContact;
  }

  @override
  void dispose() {
    _contactCtrl.dispose();
    super.dispose();
  }

  void _go(Widget p) =>
      Navigator.of(context).push(MaterialPageRoute(builder: (_) => p));

  @override
  Widget build(BuildContext context) {
    final s = AppSettings.instance;
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Family protection.
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Protect My Family',
                        style: TextStyle(
                            fontWeight: FontWeight.w700)),
                    subtitle: const Text(
                        'Extremely simple STOP guidance on risky results.'),
                    secondary:
                        const Icon(Icons.family_restroom_outlined),
                    value: s.familyMode,
                    onChanged: (v) async {
                      await s.setFamily(v);
                      if (mounted) setState(() {});
                    },
                  ),
                  TextField(
                    controller: _contactCtrl,
                    decoration: const InputDecoration(
                      border: OutlineInputBorder(),
                      labelText:
                          'Trusted contact (test number, optional)',
                      hintText: 'e.g. Mom — 98XXXXXXXX',
                    ),
                    onSubmitted: (v) async {
                      final messenger =
                          ScaffoldMessenger.of(context);
                      await s.setContact(v);
                      messenger.showSnackBar(const SnackBar(
                          content: Text(
                              'Trusted contact saved on this phone only.')));
                    },
                  ),
                ],
              ),
            ),
          ),
          SwitchListTile(
            title: const Text('Dark mode'),
            secondary: const Icon(Icons.dark_mode_outlined),
            value: s.darkMode,
            onChanged: (v) async {
              await s.setDark(v);
              if (mounted) setState(() {});
            },
          ),
          const Divider(),
          ListTile(
              leading:
                  const Icon(Icons.science_outlined),
              title: const Text('Demo Mode'),
              subtitle:
                  const Text('6 preloaded scenarios'),
              onTap: () => _go(const DemoScreen())),
          ListTile(
              leading: const Icon(
                  Icons.dashboard_outlined),
              title: const Text('Command Center'),
              subtitle: const Text(
                  'Live threat feed · analytics · sync'),
              onTap: () => _go(const CommandScreen())),
          ListTile(
              leading:
                  const Icon(Icons.privacy_tip_outlined),
              title: const Text('Privacy Center'),
              subtitle: const Text(
                  'What is stored · clear data'),
              onTap: () => _go(const PrivacyScreen())),
          ListTile(
              leading:
                  const Icon(Icons.engineering_outlined),
              title: const Text('Judge Mode'),
              subtitle: const Text(
                  'Architecture · model · latency'),
              onTap: () => _go(const JudgeScreen())),
          const Divider(),
          const ListTile(
            dense: true,
            title: Text('ScamShield v2 · Real-Time AI Fraud Firewall',
                style: TextStyle(fontSize: 12)),
            subtitle: Text(
                'On-device first. No account, no backend, no tracking.',
                style: TextStyle(fontSize: 12)),
          ),
        ],
      ),
    );
  }
}
