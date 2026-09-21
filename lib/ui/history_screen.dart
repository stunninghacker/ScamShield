import 'package:flutter/material.dart';
import '../history/history_store.dart';
import '../models/scan_result.dart';
import 'result_screen.dart';

class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key});
  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  List<ScanResult>? _items;

  @override
  void initState() {
    super.initState();
    HistoryStore().load().then((v) {
      if (mounted) setState(() => _items = v);
    });
  }

  Color _c(Verdict v) => v == Verdict.dangerous
      ? Colors.red
      : v == Verdict.suspicious
          ? Colors.orange
          : Colors.green;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('History (on-device only)'),
        actions: [
          IconButton(
            tooltip: 'Clear',
            icon: const Icon(Icons.delete_outline),
            onPressed: () async {
              await HistoryStore().clear();
              if (mounted) setState(() => _items = []);
            },
          )
        ],
      ),
      body: _items == null
          ? const Center(child: CircularProgressIndicator())
          : _items!.isEmpty
              ? const Center(child: Text('No scans yet.'))
              : ListView.builder(
                  itemCount: _items!.length,
                  itemBuilder: (_, i) {
                    final r = _items![i];
                    final preview = r.sourceText.length > 80
                        ? '${r.sourceText.substring(0, 80)}…'
                        : r.sourceText;
                    return ListTile(
                      leading: Icon(Icons.shield, color: _c(r.verdict)),
                      title: Text('${r.verdict.label} • ${r.score}/100'),
                      subtitle: Text(preview, maxLines: 2, overflow: TextOverflow.ellipsis),
                      onTap: () => Navigator.of(context).push(
                        MaterialPageRoute(builder: (_) => ResultScreen(result: r)),
                      ),
                    );
                  },
                ),
    );
  }
}
