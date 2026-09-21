import 'package:flutter/material.dart';
import '../data/demo_samples.dart';
import '../history/history_store.dart';
import '../llm/gemma_service.dart';
import '../models/scan_result.dart';
import '../rules/scam_engine.dart';
import '../share/share_handler.dart';
import 'result_screen.dart';
import 'history_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final _controller = TextEditingController();
  final _engine = const ScamEngine();
  final _share = ShareHandler();
  bool _scanning = false;
  String? _gemmaState; // null=loading, 'ready', 'fallback'

  @override
  void initState() {
    super.initState();
    _boot();
  }

  Future<void> _boot() async {
    // 1) Cold-start share (screenshot or text shared into the app).
    final initial = await _share.initialShare();
    if (initial != null && mounted && _controller.text.isEmpty) {
      _controller.text = initial.text;
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
              content: Text(initial.fromImage
                  ? 'Screenshot text extracted offline — tap Scan.'
                  : 'Shared message received — tap Scan.')),
        );
      }
    }
    // 2) Warm share stream.
    _share.listen((share) {
      if (!mounted) return;
      setState(() => _controller.text = share.text);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
            content: Text(share.fromImage
                ? 'Screenshot text extracted offline — tap Scan.'
                : 'Shared message received — tap Scan.')),
      );
    });
    // 3) Try loading the on-device model (non-blocking; fallback is fine).
    _initModel();
  }

  Future<void> _initModel() async {
    // Installs the bundled .task asset + creates the on-device session.
    // Non-blocking: rule verdicts work instantly regardless; the explainer
    // falls back to the built-in grounded template until the model is ready.
    try {
      final ok = await GemmaService.instance.init();
      if (mounted) setState(() => _gemmaState = ok ? 'ready' : 'fallback');
    } catch (_) {
      if (mounted) setState(() => _gemmaState = 'fallback');
    }
  }

  @override
  void dispose() {
    _share.dispose();
    _controller.dispose();
    super.dispose();
  }

  Future<void> _scan(String text) async {
    final trimmed = text.trim();
    if (trimmed.isEmpty || _scanning) return;
    setState(() => _scanning = true);
    try {
      // LAYER 1 — rule engine owns the verdict (instant, deterministic).
      final engineOut = _engine.analyze(trimmed);
      // LAYER 2 — on-device LLM only explains (never decides).
      final explained = await GemmaService.instance.explain(
        message: trimmed,
        signals: engineOut.signals,
        verdict: engineOut.verdict,
        score: engineOut.score,
      );
      final result = ScanResult(
        sourceText: trimmed,
        signals: engineOut.signals,
        score: engineOut.score,
        verdict: engineOut.verdict,
        explanation: explained.explanation,
        whatToDo: explained.whatToDo,
        scannedAt: DateTime.now(),
        llmUsed: explained.llmUsed,
      );
      await HistoryStore().save(result);
      if (!mounted) return;
      await Navigator.of(context).push(
        MaterialPageRoute(builder: (_) => ResultScreen(result: result)),
      );
    } finally {
      if (mounted) setState(() => _scanning = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('ScamShield'),
        actions: [
          const Padding(
            padding: EdgeInsets.only(right: 4),
            child: Chip(
              avatar: Icon(Icons.lock, size: 16),
              label: Text('Offline'),
              visualDensity: VisualDensity.compact,
            ),
          ),
          IconButton(
            tooltip: 'History (on-device)',
            icon: const Icon(Icons.history),
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const HistoryScreen()),
            ),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text('Offline scam shield. Nothing leaves your phone.',
              style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 4),
          Text(
            _gemmaState == null
                ? 'Starting on-device AI…'
                : _gemmaState == 'ready'
                    ? 'On-device AI ready • Rules + Gemma • Airplane-mode OK'
                    : 'Rule engine active • Explainer in built-in mode (model file not placed yet — see README)',
            style: Theme.of(context)
                .textTheme
                .bodySmall
                ?.copyWith(color: Colors.grey[700]),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _controller,
            minLines: 5,
            maxLines: 10,
            decoration: const InputDecoration(
              border: OutlineInputBorder(),
              hintText:
                  'Paste an SMS / WhatsApp message here…\nor Share a screenshot into ScamShield from any app.',
              labelText: 'Message to check',
            ),
          ),
          const SizedBox(height: 10),
          FilledButton.icon(
            onPressed: _scanning ? null : () => _scan(_controller.text),
            icon: _scanning
                ? const SizedBox(
                    width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.shield_outlined),
            label: Text(_scanning ? 'Scanning on-device…' : 'Scan'),
          ),
          const SizedBox(height: 16),
          Text('One-tap demo samples', style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 8),
          ...demoSamples.map((d) => Card(
                child: ListTile(
                  title: Text(d.title, style: const TextStyle(fontWeight: FontWeight.w600)),
                  subtitle: Text('${d.subtitle}  •  expects ${d.expectedVerdict}'),
                  trailing: const Icon(Icons.arrow_forward_ios, size: 16),
                  onTap: () {
                    _controller.text = d.text;
                    _scan(d.text);
                  },
                ),
              )),
          const SizedBox(height: 12),
          const Text(
            'How it works: ① share screenshot or text → ② offline OCR (if image) → '
            '③ rule engine finds suspicious spans and sets the verdict → '
            '④ on-device Gemma explains ONLY those spans. No network, ever.',
            style: TextStyle(fontSize: 12, color: Colors.grey),
          ),
        ],
      ),
    );
  }
}
