import 'package:flutter/material.dart';
import '../events/threat_events.dart';
import 'widgets/risk_widgets.dart';

/// Indicator-only history: date, category, risk, source, evidence count,
/// action taken. Full message text is never stored. Deletable.
class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key});
  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  List<ThreatEvent>? _items;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final v = await EventLog().list();
    if (mounted) setState(() => _items = v);
  }

  String _when(String iso) {
    try {
      final d = DateTime.parse(iso).toLocal();
      return '${d.day}/${d.month} ${d.hour.toString().padLeft(2, '0')}:${d.minute.toString().padLeft(2, '0')}';
    } catch (_) {
      return '';
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
            Text(
                '${_when(e.timestamp)} · source: ${e.source} · score ${e.score}/100 · '
                'confidence ${e.confidence.toStringAsFixed(2)} · action: ${e.action}'
                '${e.demo ? ' · DEMO DATA' : ''}'),
            const SizedBox(height: 8),
            Text('“${e.preview}”',
                style: const TextStyle(fontStyle: FontStyle.italic)),
            const SizedBox(height: 8),
            const Text('Signals:',
                style: TextStyle(fontWeight: FontWeight.w700)),
            Wrap(
              spacing: 6,
              children: e.signals
                  .map((s) => Chip(
                      label: Text(s),
                      visualDensity: VisualDensity.compact))
                  .toList(),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scam History'),
        actions: [
          IconButton(
            tooltip: 'Delete all',
            icon: const Icon(Icons.delete_outline),
            onPressed: () async {
              final ok = await showDialog<bool>(
                  context: context,
                  builder: (_) => AlertDialog(
                        title: const Text('Delete all history?'),
                        content: const Text(
                            'Removes every locally stored indicator. Cannot be undone.'),
                        actions: [
                          TextButton(
                              onPressed: () =>
                                  Navigator.of(context).pop(false),
                              child: const Text('Cancel')),
                          FilledButton(
                              onPressed: () =>
                                  Navigator.of(context).pop(true),
                              child: const Text('Delete')),
                        ],
                      ));
              if (ok == true) {
                await EventLog().clear();
                await _load();
              }
            },
          )
        ],
      ),
      body: _items == null
          ? const Center(child: CircularProgressIndicator())
          : _items!.isEmpty
              ? const Center(
                  child: Padding(
                  padding: EdgeInsets.all(24),
                  child: Text(
                      'No scans yet.\nHistory stores indicators only (risk, category, signals) — never full recordings.',
                      textAlign: TextAlign.center),
                ))
              : ListView(
                  padding: const EdgeInsets.all(12),
                  children: [
                    const Card(
                        child: ListTile(
                            dense: true,
                            leading: Icon(Icons.privacy_tip_outlined),
                            title: Text(
                                'Stored on this phone only: risk, category, signal list, redacted preview. Tap any row for detail. Delete anytime above.',
                                style: TextStyle(fontSize: 12)))),
                    for (final e in _items!)
                      Card(
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
                              '${_when(e.timestamp)} · ${e.source}${e.family.isNotEmpty ? ' · ${e.family}' : ''} · ${e.evidenceCount} evidence · ${e.action}',
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis),
                          trailing: Text('${e.score}',
                              style: const TextStyle(
                                  fontWeight: FontWeight.w800,
                                  fontSize: 18)),
                          onTap: () => _detail(e),
                        ),
                      ),
                  ],
                ),
    );
  }
}
