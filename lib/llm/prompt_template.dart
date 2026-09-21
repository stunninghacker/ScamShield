/// EXACT LLM prompt template. The model ONLY explains — it never decides.
///
/// Hard rules baked into the prompt:
///  1. Explain ONLY the signals listed in {signals}. Never invent new ones.
///  2. Never change or mention a different verdict.
///  3. Quote the matched text exactly when referring to a signal.
///  4. If {signals} is empty, reassure + give one generic OTP hygiene tip.
///  5. Plain language a non-technical parent understands. No jargon.
///  6. Short: <= 90 words explanation + 1 action line. Offline, small model.
library;

import '../models/signal_match.dart';
import '../models/scan_result.dart';

class PromptTemplate {
  static const systemRules = '''
You are ScamShield, an on-device explainer. You do NOT detect scams.
A deterministic rule engine already decided the verdict and found the signals.
Your job: explain those signals in plain, kind language.

STRICT RULES (never break):
- Only explain signals from the SIGNALS list below. Never invent new reasons.
- Never change the verdict. Never say safe if verdict is dangerous and vice versa.
- When you mention a signal, quote its matched text EXACTLY in "quotes".
- No technical jargon (no "heuristic", "vector", "entropy"). Simple words.
- Do not repeat the full message. Do not add links, phone numbers, or URLs.
- If SIGNALS is empty: say the message looks genuine, name one thing that is GOOD (e.g. no link, no OTP request), and remind: never share OTP with anyone.
- Keep EXPLANATION under 90 words. Then one WHAT TO DO line.
''';

  /// Builds the full user prompt for the on-device model.
  static String build({
    required String message,
    required List<SignalMatch> signals,
    required Verdict verdict,
    required int score,
  }) {
    final buf = StringBuffer();
    buf.writeln(systemRules);
    buf.writeln('VERDICT: ${verdict.nameUpper} (score $score/100).');
    // Truncate very long messages for the small on-device model.
    final shortMsg = message.length > 800 ? '${message.substring(0, 800)}…' : message;
    buf.writeln('MESSAGE: """$shortMsg"""');
    if (signals.isEmpty) {
      buf.writeln('SIGNALS: (none)');
    } else {
      buf.writeln('SIGNALS:');
      for (final s in signals) {
        buf.writeln('- [${s.id}] ${s.label}: "${s.matchedText}" (${s.detail})');
      }
    }
    buf.writeln('''
Respond in EXACTLY this format:
EXPLANATION: <2-4 short sentences, each tied to one quoted signal above>
WHAT TO DO: <one short line telling the user the safest next step>''');
    return buf.toString();
  }

  /// Deterministic fallback used when the Gemma model is missing/failed.
  /// Guarantees the demo never crashes and NEVER contradicts the verdict.
  static ({String explanation, String whatToDo}) fallback({
    required List<SignalMatch> signals,
    required Verdict verdict,
  }) {
    if (signals.isEmpty) {
      return (
        explanation:
            'This message looks genuine. It has no link and does not ask for any OTP, PIN or password. Real bank alerts only inform you — they never ask for secrets.',
        whatToDo: 'No action needed — but never share OTP or PIN with anyone who calls.',
      );
    }
    final byId = <String, List<SignalMatch>>{};
    for (final s in signals) {
      byId.putIfAbsent(s.id, () => []).add(s);
    }
    final parts = <String>[];
    void add(String id, String sentence) {
      final list = byId[id];
      if (list == null || list.isEmpty) return;
      final quoted = list.map((s) => '"${s.matchedText}"').join(', ');
      parts.add(sentence.replaceFirst('{q}', quoted));
    }

    add('LINK_RISK', 'It contains a risky link {q} — real banks never use such links.');
    add('SECRET_REQUEST', 'It asks for a secret {q} — banks never ask for OTP, PIN or CVV.');
    add('URGENCY_THREAT', 'It pressures you with {q} to stop you thinking.');
    add('REWARD_LURE', 'It tempts you with a prize/refund {q} to make you pay.');
    add('PAYMENT_PULL', 'It pushes a payment to {q} — a real prize never needs a fee.');
    add('CALLBACK', 'It gives a callback number {q} so scammers can trick you on call.');
    add('IMPERSONATION', 'It pretends to be {q} to look trustworthy.');

    final explanation = parts.join(' ');
    final whatToDo = verdict == Verdict.dangerous
        ? 'Do not click, pay, or share any code — delete it and report as spam.'
        : 'Do not click or pay yet — verify via the official app or website first.';
    return (explanation: explanation, whatToDo: whatToDo);
  }
}
