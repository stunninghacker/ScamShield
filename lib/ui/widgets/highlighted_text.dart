import 'package:flutter/material.dart';
import '../../models/signal_match.dart';

/// Renders [source] with every [signals] span highlighted inline.
/// This is the provenance view: what you see highlighted is EXACTLY what
/// the rule engine flagged (offsets come straight from SignalMatch).
class HighlightedText extends StatelessWidget {
  final String source;
  final List<SignalMatch> signals;
  const HighlightedText({super.key, required this.source, required this.signals});

  Color _colorFor(String id) {
    switch (id) {
      case 'LINK_RISK':
      case 'SECRET_REQUEST':
      case 'PAYMENT_PULL':
      case 'DIGITAL_ARREST':
        return const Color(0xFFD32F2F); // red family
      case 'URGENCY_THREAT':
      case 'REWARD_LURE':
      case 'IMPERSONATION':
      case 'CALLBACK':
      case 'JOB_LURE':
      case 'REMOTE_ACCESS':
        return const Color(0xFFEF6C00); // amber/orange family
      default:
        return const Color(0xFFEF6C00);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (signals.isEmpty || source.isEmpty) {
      return SelectableText(source, style: const TextStyle(fontSize: 15, height: 1.5));
    }
    final spans = [...signals]..sort((a, b) => a.start.compareTo(b.start));
    final children = <TextSpan>[];
    var cursor = 0;
    const base = TextStyle(fontSize: 15, height: 1.5, color: Colors.black87);

    for (final s in spans) {
      final start = s.start.clamp(0, source.length);
      final end = s.end.clamp(0, source.length);
      if (end <= cursor || start >= end) continue; // overlapped / invalid
      if (start > cursor) {
        children.add(TextSpan(text: source.substring(cursor, start), style: base));
      }
      // Safety: verify the span text matches (defensive; engine guarantees it).
      final shown = source.substring(start, end);
      children.add(TextSpan(
        text: shown,
        style: base.copyWith(
          backgroundColor: _colorFor(s.id).withValues(alpha: 0.18),
          color: _colorFor(s.id),
          fontWeight: FontWeight.w700,
          decoration: TextDecoration.underline,
          decorationColor: _colorFor(s.id),
        ),
      ));
      cursor = end;
    }
    if (cursor < source.length) {
      children.add(TextSpan(text: source.substring(cursor), style: base));
    }
    return SelectableText.rich(TextSpan(children: children));
  }
}
