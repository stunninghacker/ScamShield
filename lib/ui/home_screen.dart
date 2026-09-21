import 'package:flutter/material.dart';
import '../events/threat_events.dart';
import '../llm/gemma_service.dart';
import '../settings/app_settings.dart';
import '../share/share_handler.dart';
import 'command_screen.dart';
import 'demo_screen.dart';
import 'lens_screen.dart';
import 'radar_screen.dart';
import 'scan_actions.dart';
import 'timeline_screen.dart';
import 'widgets/risk_widgets.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final _controller = TextEditingController();
  final _share = ShareHandler();
  List<ThreatEvent> _recent = [];
  String? _gemmaState;

  @override
  void initState() {
    super.initState();
    _boot();
    _refresh();
  }

  Future<void> _boot() async {
    final initial = await _share.initialShare();
    if (initial != null && mounted && _controller.text.isEmpty) {
      _controller.text = initial.text;
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
            content: Text(initial.fromImage
                ? 'Screenshot text extracted offline — tap Scan.'
                : 'Shared message received — tap Scan.')));
      }
    }
    _share.listen((share) {
      if (!mounted) return;
      setState(() => _controller.text = share.text);
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text(share.fromImage
              ? 'Screenshot text extracted offline — tap Scan.'
              : 'Shared message received — tap Scan.')));
    });
    try {
      final ok = await GemmaService.instance.init();
      if (mounted) setState(() => _gemmaState = ok ? 'ready' : 'fallback');
    } catch (_) {
      if (mounted) setState(() => _gemmaState = 'fallback');
    }
  }

  Future<void> _refresh() async {
    final items = await EventLog().list();
    if (mounted) setState(() => _recent = items.take(3).toList());
  }

  @override
  void dispose() {
    _share.dispose();
    _controller.dispose();
    super.dispose();
  }

  void _go(Widget page) => Navigator.of(context)
      .push(MaterialPageRoute(builder: (_) => page))
      .then((_) => _refresh());

  @override
  Widget build(BuildContext context) {
    final threats = _recent.where((e) => e.risk == 'dangerous').length;
    return Scaffold(
      appBar: AppBar(
        title: const Text('ScamShield'),
        actions: const [
          Padding(
            padding: EdgeInsets.only(right: 12),
            child: Chip(
              avatar: Icon(Icons.lock, size: 16),
              label: Text('Offline'),
              visualDensity: VisualDensity.compact,
            ),
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _refresh,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            // Hero: protection status.
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(14),
                      decoration: BoxDecoration(
                        color: Theme.of(context)
                            .colorScheme
                            .primaryContainer,
                        shape: BoxShape.circle,
                      ),
                      child: Icon(Icons.shield,
                          size: 36,
                          color: Theme.of(context)
                              .colorScheme
                              .onPrimaryContainer),
                    ),
                    const SizedBox(width: 14),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text('Your AI fraud firewall',
                              style: TextStyle(
                                  fontSize: 18,
                                  fontWeight: FontWeight.w800)),
                          Text(
                              threats == 0
                                  ? 'Protection active — no high-risk events'
                                  : '$threats high-risk event(s) detected',
                              style: TextStyle(
                                  color: threats == 0
                                      ? Colors.green
                                      : Colors.red,
                                  fontWeight: FontWeight.w600)),
                          Text(
                            _gemmaState == null
                                ? 'Starting on-device AI…'
                                : _gemmaState == 'ready'
                                    ? 'Rules + Gemma on-device'
                                    : 'Rules + built-in explainer',
                            style: const TextStyle(
                                fontSize: 12, color: Colors.grey),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _controller,
              minLines: 4,
              maxLines: 8,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                hintText:
                    'Paste an SMS / WhatsApp message… or Share one into ScamShield.',
                labelText: 'Message to check',
              ),
            ),
            const SizedBox(height: 10),
            FilledButton.icon(
              onPressed: () => runTextScan(context, _controller.text)
                  .then((_) => _refresh()),
              icon: const Icon(Icons.shield_outlined),
              label: const Text('Scan message'),
            ),
            const SizedBox(height: 16),
            Text('Protect',
                style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 8),
            GridView.count(
              crossAxisCount: 3,
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              mainAxisSpacing: 8,
              crossAxisSpacing: 8,
              childAspectRatio: 1.05,
              children: [
                _Feature(Icons.qr_code_scanner, 'ScamLens',
                    'QR · URL · Photo', () => _go(const LensScreen())),
                _Feature(Icons.radar, 'Scam Radar',
                    'Live call check', () => _go(const RadarScreen())),
                _Feature(Icons.science_outlined, 'Demo Mode',
                    '6 scenarios', () => _go(const DemoScreen())),
                _Feature(Icons.timeline_outlined, 'Attack chain',
                    'KYC timeline', () => _go(const TimelineScreen())),
                _Feature(Icons.dashboard_outlined, 'Command',
                    'Threat center', () => _go(const CommandScreen())),
                _Feature(
                    AppSettings.instance.familyMode
                        ? Icons.family_restroom
                        : Icons.person_outline,
                    AppSettings.instance.familyMode
                        ? 'Family: ON'
                        : 'Family: off',
                    'Simple mode', () => _go(const DemoScreen())),
              ],
            ),
            const SizedBox(height: 16),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text('Recent activity',
                    style: Theme.of(context).textTheme.titleSmall),
                TextButton(
                    onPressed: () =>
                        setState(() => _refresh()),
                    child: const Text('Refresh')),
              ],
            ),
            if (_recent.isEmpty)
              const Card(
                  child: ListTile(
                      leading: Icon(Icons.check_circle_outline),
                      title: Text('Nothing scanned yet'),
                      subtitle: Text(
                          'Scans appear here with risk, category and evidence count.'))),
            for (final e in _recent)
              Card(
                child: ListTile(
                  leading: Icon(riskIcon(verdictFromRisk(e.risk)),
                      color: riskColor(
                          verdictFromRisk(e.risk), context)),
                  title: Text(
                      '${e.risk.toUpperCase()} · ${e.category}',
                      style:
                          const TextStyle(fontWeight: FontWeight.w700)),
                  subtitle: Text(
                      '${e.source} · ${e.evidenceCount} evidence · ${e.action}',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis),
                  trailing: Text('${e.score}',
                      style: const TextStyle(
                          fontWeight: FontWeight.w800, fontSize: 18)),
                ),
              ),
            const SizedBox(height: 8),
            const Text(
              'On-device analysis. History stores indicators only — never full recordings. See Settings → Privacy Center.',
              style: TextStyle(fontSize: 12, color: Colors.grey),
            ),
          ],
        ),
      ),
    );
  }
}

class _Feature extends StatelessWidget {
  final IconData icon;
  final String title;
  final String sub;
  final VoidCallback onTap;
  const _Feature(this.icon, this.title, this.sub, this.onTap);

  @override
  Widget build(BuildContext context) {
    return Card(
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(8),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(icon,
                  size: 28,
                  color: Theme.of(context).colorScheme.primary),
              const SizedBox(height: 4),
              Text(title,
                  style: const TextStyle(
                      fontWeight: FontWeight.w700, fontSize: 12),
                  textAlign: TextAlign.center),
              Text(sub,
                  style:
                      const TextStyle(fontSize: 10, color: Colors.grey),
                  textAlign: TextAlign.center),
            ],
          ),
        ),
      ),
    );
  }
}
