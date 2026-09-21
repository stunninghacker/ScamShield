import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../analysis/scan_pipeline.dart';
import '../data/demo_scenarios.dart';
import '../models/verdict.dart';
import '../rules/scam_engine.dart';
import 'result_screen.dart';
import 'widgets/risk_widgets.dart';

/// Scam Radar — SIMULATED live-conversation check.
///
/// Streams a scripted scam-call transcript (clearly labeled simulated: no
/// microphone, no recording, no STT) and recomputes risk on the cumulative
/// transcript after every line, so judges watch urgency → impersonation →
/// OTP demand light up in real time.
class RadarScreen extends StatefulWidget {
  const RadarScreen({super.key});
  @override
  State<RadarScreen> createState() => _RadarScreenState();
}

class _RadarScreenState extends State<RadarScreen> {
  static const _engine = ScamEngine();
  final _shown = <RadarLine>[];
  int _next = 0;
  bool _playing = false;
  bool _done = false;
  int _score = 0;
  Set<String> _signals = {};
  Verdict _live = Verdict.safe;

  Future<void> _play() async {
    if (_playing) return;
    setState(() {
      _playing = true;
      if (_done) {
        _shown.clear();
        _next = 0;
        _done = false;
        _score = 0;
        _signals = {};
        _live = Verdict.safe;
      }
    });
    while (_next < radarArrestScript.length && mounted && _playing) {
      await Future.delayed(const Duration(milliseconds: 1400));
      if (!mounted || !_playing) break;
      setState(() {
        _shown.add(radarArrestScript[_next++]);
        final full = _shown.map((l) => l.text).join(' ');
        final r = _engine.analyze(full);
        final was = _live;
        _score = r.score;
        _live = r.verdict;
        _signals = r.signals.map((s) => s.id).toSet();
        if (_live == Verdict.dangerous && was != Verdict.dangerous) {
          HapticFeedback.heavyImpact();
        }
      });
    }
    if (mounted) {
      setState(() {
        _playing = false;
        if (_next >= radarArrestScript.length) _done = true;
      });
    }
  }

  Future<void> _finish() async {
    final full = _shown.map((l) => l.text).join(' ');
    showDialog(
        context: context,
        barrierDismissible: false,
        builder: (_) =>
            const Center(child: CircularProgressIndicator()));
    final result = await ScanPipeline.instance
        .analyze(full, source: 'voice', demo: true);
    if (!mounted) return;
    Navigator.of(context).pop();
    await Navigator.of(context).push(MaterialPageRoute(
        builder: (_) =>
            ResultScreen(result: result, staged: true)));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Scam Radar')),
      body: Column(
        children: [
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(12),
            color: Theme.of(context)
                .colorScheme
                .surfaceContainerHighest,
            child: const Text(
              'SIMULATED CALL — scripted demo transcript. No microphone is used and nothing is recorded.',
              style: TextStyle(fontSize: 12),
              textAlign: TextAlign.center,
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(12),
            child: Row(children: [
              RiskBadge(verdict: _live),
              const SizedBox(width: 10),
              Expanded(
                  child: ScoreBar(
                      score: _score, verdict: _live)),
            ]),
          ),
          if (_signals.isNotEmpty)
            SizedBox(
              height: 40,
              child: ListView(
                scrollDirection: Axis.horizontal,
                padding:
                    const EdgeInsets.symmetric(horizontal: 12),
                children: _signals
                    .map((s) => Padding(
                        padding:
                            const EdgeInsets.only(right: 6),
                        child: Chip(
                            label: Text(s),
                            visualDensity:
                                VisualDensity.compact)))
                    .toList(),
              ),
            ),
          Expanded(
            child: _shown.isEmpty
                ? const Center(
                    child: Text(
                        'Press Play — a “CBI officer” is calling…',
                        style: TextStyle(color: Colors.grey)))
                : ListView.builder(
                    padding: const EdgeInsets.all(12),
                    itemCount: _shown.length,
                    itemBuilder: (_, i) {
                      final l = _shown[i];
                      final me = l.speaker == 'You';
                      return Align(
                        alignment: me
                            ? Alignment.centerRight
                            : Alignment.centerLeft,
                        child: Container(
                          margin: const EdgeInsets.symmetric(
                              vertical: 4),
                          padding:
                              const EdgeInsets.all(10),
                          constraints: BoxConstraints(
                              maxWidth:
                                  MediaQuery.of(context)
                                          .size
                                          .width *
                                      0.8),
                          decoration: BoxDecoration(
                            color: me
                                ? Theme.of(context)
                                    .colorScheme
                                    .primaryContainer
                                : Theme.of(context)
                                    .colorScheme
                                    .surfaceContainerHighest,
                            borderRadius:
                                BorderRadius.circular(12),
                          ),
                          child: Column(
                            crossAxisAlignment:
                                CrossAxisAlignment.start,
                            children: [
                              Text(l.speaker,
                                  style: const TextStyle(
                                      fontSize: 11,
                                      fontWeight:
                                          FontWeight.w700,
                                      color: Colors.grey)),
                              Text(l.text,
                                  style: const TextStyle(
                                      fontSize: 14)),
                            ],
                          ),
                        ),
                      );
                    },
                  ),
          ),
          Padding(
            padding: const EdgeInsets.all(12),
            child: Row(children: [
              Expanded(
                child: FilledButton.icon(
                  onPressed: _playing ? null : _play,
                  icon: Icon(_done
                      ? Icons.replay_outlined
                      : Icons.play_arrow_outlined),
                  label: Text(_done
                      ? 'Replay'
                      : _shown.isEmpty
                          ? 'Play simulated call'
                          : 'Continue'),
                ),
              ),
              if (_playing) ...[
                const SizedBox(width: 8),
                OutlinedButton(
                    onPressed: () =>
                        setState(() => _playing = false),
                    child: const Text('Pause')),
              ],
              if (_done) ...[
                const SizedBox(width: 8),
                FilledButton.tonal(
                    onPressed: _finish,
                    child:
                        const Text('Full report')),
              ],
            ]),
          ),
        ],
      ),
    );
  }
}
