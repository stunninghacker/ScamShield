import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../events/threat_events.dart';
import 'widgets/risk_widgets.dart';

/// Office Kit — Command Center (on-device).
///
/// Live feed of the local threat-event log, analytics computed from real
/// on-device data (labeled as such), and phone↔desktop sync via
/// user-initiated clipboard JSON export/import — offline, no backend.
class CommandScreen extends StatefulWidget {
  const CommandScreen({super.key});
  @override
  State<CommandScreen> createState() => _CommandScreenState();
}

class _CommandScreenState extends State<CommandScreen> {
  List<ThreatEvent> _events = [];
  Timer? _poll;
  String _filter = 'ALL';

  @override
  void initState() {
    super.initState();
    _load();
    _poll = Timer.periodic(
        const Duration(seconds: 2), (_) => _load(silent: true));
  }

  @override
  void dispose() {
    _poll?.cancel();
    super.dispose();
  }

  Future<void> _load({bool silent = false}) async {
    final v = await EventLog().list();
    if (!mounted) return;
    final changed = v.length != _events.length ||
        (v.isNotEmpty &&
            _events.isNotEmpty &&
            v.first.id != _events.first.id);
    if (changed || !silent) setState(() => _events = v);
  }

  List<ThreatEvent> get _filtered {
    switch (_filter) {
      case 'HIGH':
        return _events.where((e) => e.risk == 'dangerous').toList();
      case 'MEDIUM':
        return _events.where((e) => e.risk == 'suspicious').toList();
      case 'LOW':
        return _events.where((e) => e.risk == 'safe').toList();
      default:
        return _events;
    }
  }

  Future<void> _export() async {
    final json = await EventLog().exportJson();
    await Clipboard.setData(ClipboardData(text: json));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text(
            'Copied ${_events.length} event(s) as sync JSON. Paste it in the desktop app → Import.')));
  }

  Future<void> _import() async {
    final ctrl = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Import sync JSON'),
        content: TextField(
          controller: ctrl,
          maxLines: 6,
          decoration: const InputDecoration(
              border: OutlineInputBorder(),
              hintText: 'Paste exported events JSON…'),
        ),
        actions: [
          TextButton(
              onPressed: () =>
                  Navigator.of(context).pop(false),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () =>
                  Navigator.of(context).pop(true),
              child: const Text('Import')),
        ],
      ),
    );
    if (ok != true || ctrl.text.trim().isEmpty) return;
    try {
      final n = await EventLog().importJson(ctrl.text.trim());
      await _load();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Imported $n event(s).')));
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Import failed: $e')));
    }
  }

  void _detail(ThreatEvent e) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (_) => DraggableScrollableSheet(
        expand: false,
        builder: (_, ctrl) => ListView(
          controller: ctrl,
          padding: const EdgeInsets.all(20),
          children: [
            Row(children: [
              RiskBadge(verdict: verdictFromRisk(e.risk)),
              const SizedBox(width: 8),
              Expanded(
                  child: Text(e.category,
                      style: const TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.w800))),
            ]),
            const SizedBox(height: 8),
            Text('LIVE SECURITY EVENT',
                style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                    color: Theme.of(context)
                        .colorScheme
                        .primary)),
            Text('Risk: ${e.risk.toUpperCase()} (${e.score}/100)'),
            Text('Source: ${e.source}'),
            Text(
                'Time: ${e.timestamp.substring(0, 16).replaceAll('T', ' ')}'),
            if (e.stage != null) Text('Chain stage: ${e.stage}'),
            if (e.chainId != null)
              Text('Chain: ${e.chainId!.substring(0, 13)}…'),
            const SizedBox(height: 8),
            const Text('Signals:',
                style: TextStyle(fontWeight: FontWeight.w700)),
            Wrap(
              spacing: 6,
              children: [
                for (final s in e.signals)
                  Chip(
                      label: Text('✓ $s'),
                      visualDensity: VisualDensity.compact),
              ],
            ),
            const SizedBox(height: 8),
            Text('“${e.preview}”',
                style:
                    const TextStyle(fontStyle: FontStyle.italic)),
            const SizedBox(height: 8),
            Text('Recommended action: ${e.action}',
                style:
                    const TextStyle(fontWeight: FontWeight.w700)),
          ],
        ),
      ),
    );
  }

  Future<void> _simulate() async {    await EventLog().log(ThreatEvent(
      id: EventLog.newId(),
      timestamp: DateTime.now().toIso8601String(),
      source: 'voice',
      category: 'Digital Arrest',
      risk: 'dangerous',
      score: 92,
      confidence: 0.9,
      signals: const ['DIGITAL_ARREST', 'URGENCY_THREAT', 'SECRET_REQUEST'],
      evidenceCount: 5,
      preview: 'Simulated digital-arrest call transcript (demo data)…',
      demo: true,
    ));
    await _load();
  }

  @override
  Widget build(BuildContext context) {
    final high =
        _events.where((e) => e.risk == 'dangerous').length;
    final med =
        _events.where((e) => e.risk == 'suspicious').length;
    final byCat = <String, int>{};
    final bySig = <String, int>{};
    for (final e in _events) {
      byCat[e.category] = (byCat[e.category] ?? 0) + 1;
      for (final s in e.signals) {
        bySig[s] = (bySig[s] ?? 0) + 1;
      }
    }
    final topCat = byCat.entries.isEmpty
        ? '—'
        : byCat.entries
            .reduce((a, b) => a.value >= b.value ? a : b)
            .key;
    final topSig = bySig.entries.isEmpty
        ? '—'
        : bySig.entries
            .reduce((a, b) => a.value >= b.value ? a : b)
            .key;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Command Center'),
        actions: [
          IconButton(
              tooltip: 'Export sync JSON',
              icon: const Icon(Icons.upload_outlined),
              onPressed: _export),
          IconButton(
              tooltip: 'Import sync JSON',
              icon:
                  const Icon(Icons.download_outlined),
              onPressed: _import),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Analytics (real local data, labeled).
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment:
                    CrossAxisAlignment.start,
                children: [
                  const Text('Analytics · this device',
                      style: TextStyle(
                          fontWeight: FontWeight.w800)),
                  const SizedBox(height: 6),
                  Row(
                    mainAxisAlignment:
                        MainAxisAlignment.spaceAround,
                    children: [
                      _stat('${_events.length}',
                          'Detected'),
                      _stat('$high', 'High risk'),
                      _stat('$med', 'Medium'),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text('Top category: $topCat'),
                  Text('Top signal: $topSig'),
                ],
              ),
            ),
          ),
          const SizedBox(height: 8),
          // Live feed filters.
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(children: [
              for (final f in ['ALL', 'HIGH', 'MEDIUM', 'LOW'])
                Padding(
                  padding: const EdgeInsets.only(right: 6),
                  child: ChoiceChip(
                    label: Text(f),
                    selected: _filter == f,
                    onSelected: (_) =>
                        setState(() => _filter = f),
                  ),
                ),
              TextButton.icon(
                  onPressed: _simulate,
                  icon: const Icon(
                      Icons.bolt_outlined,
                      size: 16),
                  label: const Text('Simulate live event')),
            ]),
          ),
          const SizedBox(height: 4),
          const Text('LIVE SECURITY EVENTS',
              style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w700,
                  color: Colors.grey)),
          if (_filtered.isEmpty)
            const Card(
                child: ListTile(
                    title: Text('No events yet'),
                    subtitle: Text(
                        'Run any scan — it appears here live.'))),
          for (final e in _filtered)
            Card(
              color: e.risk == 'dangerous'
                  ? Colors.red.withValues(alpha: 0.06)
                  : null,
              child: ListTile(
                leading: Icon(
                    riskIcon(verdictFromRisk(e.risk)),
                    color: riskColor(
                        verdictFromRisk(e.risk), context)),
                title: Text(
                    '${e.risk.toUpperCase()} · ${e.category}${e.demo ? ' (demo)' : ''}',
                    style: const TextStyle(
                        fontWeight: FontWeight.w700)),
                subtitle: Text(
                    '${e.source} · ${e.timestamp.substring(0, 16).replaceAll('T', ' ')} · ${e.signals.join(', ')} · → ${e.action}'),
                onTap: () => _detail(e),
              ),
            ),
          const SizedBox(height: 8),
          const Text(
            'Sync: Export copies events as JSON — paste into Import on the desktop build. No servers involved.',
            style: TextStyle(fontSize: 12, color: Colors.grey),
          ),
        ],
      ),
    );
  }

  Widget _stat(String n, String label) => Column(children: [
        Text(n,
            style: const TextStyle(
                fontSize: 24, fontWeight: FontWeight.w900)),
        Text(label, style: const TextStyle(fontSize: 12)),
      ]);
}
