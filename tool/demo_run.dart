/// Headless end-to-end demo: runs the 4 bundled samples through the exact
/// same pipeline the UI uses (ScamEngine -> PromptTemplate.fallback, which
/// is what shows until the Gemma .task file is bundled).
/// Run: dart tool/demo_run.dart
library;
// ignore_for_file: avoid_print
import 'package:scamshield/data/demo_samples.dart';
import 'package:scamshield/llm/prompt_template.dart';
import 'package:scamshield/models/verdict.dart';
import 'package:scamshield/rules/scam_engine.dart';

void main() {
  const engine = ScamEngine();
  for (var i = 0; i < demoSamples.length; i++) {
    final d = demoSamples[i];
    final r = engine.analyze(d.text);
    final fb = PromptTemplate.fallback(
        signals: r.signals, verdict: r.verdict);
    print('=== Sample ${i + 1}: ${d.title} ===');
    print('Message: ${d.text}');
    print('Verdict: ${r.verdict.label.toUpperCase()} '
        '(score ${r.score}/100, expects ${d.expectedVerdict})');
    print('Signals (${r.signals.length} spans):');
    for (final s in r.signals) {
      print('  [${s.id}] "${s.matchedText}" '
          '@${s.start}:${s.end} (${s.detail})');
    }
    print('Explanation: ${fb.explanation}');
    print('What to do: ${fb.whatToDo}');
    print('');
  }
}
