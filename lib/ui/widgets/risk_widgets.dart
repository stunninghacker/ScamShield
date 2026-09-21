/// Shared risk visuals: icon+text+color (never color alone), score bar.
library;

import 'package:flutter/material.dart';
import '../../models/verdict.dart';

Color riskColor(Verdict v, BuildContext context) {
  switch (v) {
    case Verdict.dangerous:
      return const Color(0xFFD32F2F);
    case Verdict.suspicious:
      return const Color(0xFFEF6C00);
    case Verdict.safe:
      return const Color(0xFF2E7D32);
  }
}

Color riskBg(Verdict v, BuildContext context) {
  final dark = Theme.of(context).brightness == Brightness.dark;
  switch (v) {
    case Verdict.dangerous:
      return dark ? const Color(0xFF4A1111) : const Color(0xFFFFEBEE);
    case Verdict.suspicious:
      return dark ? const Color(0xFF4A2C00) : const Color(0xFFFFF3E0);
    case Verdict.safe:
      return dark ? const Color(0xFF0F3D1C) : const Color(0xFFE8F5E9);
  }
}

IconData riskIcon(Verdict v) {
  switch (v) {
    case Verdict.dangerous:
      return Icons.dangerous_outlined;
    case Verdict.suspicious:
      return Icons.warning_amber_outlined;
    case Verdict.safe:
      return Icons.verified_outlined;
  }
}

Verdict verdictFromRisk(String risk) {
  switch (risk) {
    case 'dangerous':
      return Verdict.dangerous;
    case 'suspicious':
      return Verdict.suspicious;
    default:
      return Verdict.safe;
  }
}

/// Pill showing icon + HIGH/MEDIUM/LOW text.
class RiskBadge extends StatelessWidget {
  final Verdict verdict;
  final bool compact;
  const RiskBadge({super.key, required this.verdict, this.compact = false});

  @override
  Widget build(BuildContext context) {
    final c = riskColor(verdict, context);
    return Container(
      padding: EdgeInsets.symmetric(
          horizontal: compact ? 8 : 12, vertical: compact ? 3 : 6),
      decoration: BoxDecoration(
        color: c.withValues(alpha: 0.14),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: c),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(riskIcon(verdict), size: compact ? 14 : 18, color: c),
          const SizedBox(width: 4),
          Text(verdict.riskWord,
              style: TextStyle(
                  color: c,
                  fontWeight: FontWeight.w800,
                  fontSize: compact ? 11 : 13)),
        ],
      ),
    );
  }
}

/// Animated 0..100 score bar with numeric label.
class ScoreBar extends StatelessWidget {
  final int score;
  final Verdict verdict;
  const ScoreBar({super.key, required this.score, required this.verdict});

  @override
  Widget build(BuildContext context) {
    final c = riskColor(verdict, context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            const Text('ScamShield risk score',
                style: TextStyle(fontSize: 12, color: Colors.grey)),
            Text('$score/100',
                style:
                    TextStyle(fontWeight: FontWeight.w800, color: c)),
          ],
        ),
        const SizedBox(height: 4),
        ClipRRect(
          borderRadius: BorderRadius.circular(6),
          child: TweenAnimationBuilder<double>(
            tween: Tween(begin: 0, end: score / 100),
            duration: const Duration(milliseconds: 700),
            builder: (_, v, __) => LinearProgressIndicator(
              value: v,
              minHeight: 10,
              backgroundColor:
                  Theme.of(context).colorScheme.surfaceContainerHighest,
              valueColor: AlwaysStoppedAnimation(c),
            ),
          ),
        ),
        const Text('Internal heuristic — not a guarantee.',
            style: TextStyle(fontSize: 11, color: Colors.grey)),
      ],
    );
  }
}
