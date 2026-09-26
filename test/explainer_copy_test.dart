import 'package:flutter_test/flutter_test.dart';
import 'package:scamshield/analysis/attack_chain.dart';
import 'package:scamshield/analysis/explainer_copy.dart';
import 'package:scamshield/analysis/verdict_report.dart';
import 'package:scamshield/models/verdict.dart';

void main() {
  group('explainer copy covers every signal and family', () {
    test('plain title + why for every engine signal class', () {
      for (final id in signalLabels.keys) {
        expect(plainSignalTitle[id], isNotNull,
            reason: '$id needs a plain title');
        expect(plainSignalTitle[id], isNotEmpty);
        expect(plainSignalWhy[id], isNotNull,
            reason: '$id needs a plain why');
        expect(plainSignalWhy[id], isNotEmpty);
      }
    });
    test('no invented signals: copy keys match the engine exactly', () {
      expect(plainSignalTitle.keys.toSet(), signalLabels.keys.toSet());
      expect(plainSignalWhy.keys.toSet(), signalLabels.keys.toSet());
    });
    test('family advice for every family', () {
      for (final f in ScamFamily.values) {
        expect(familyAdvice[f], isNotNull, reason: '$f needs advice');
        expect(familyAdvice[f], isNotEmpty);
      }
    });
    test('recommended actions for every verdict', () {
      for (final v in Verdict.values) {
        expect(recommendedActions(v), isNotEmpty, reason: '$v');
      }
      expect(recommendedActions(Verdict.dangerous).first,
          contains('Stop'));
      expect(
          recommendedActions(Verdict.safe).first, contains('Nothing'));
    });
  });

  group('no jargon in the default view', () {
    const banned = [
      'heuristic',
      'LLM',
      'Gemma',
      'vector',
      'NSE',
      'payload',
      'entropy',
      'regex',
      'breakdown',
      'confidence interval',
      'false positive',
    ];
    Iterable<String> allDefaultStrings() sync* {
      yield* plainSignalTitle.values;
      yield* plainSignalWhy.values;
      yield* familyAdvice.values;
      for (final v in Verdict.values) {
        yield* recommendedActions(v);
      }
    }

    test('default strings avoid technical terms', () {
      for (final s in allDefaultStrings()) {
        for (final b in banned) {
          expect(s.toLowerCase().contains(b.toLowerCase()), isFalse,
              reason: 'jargon "$b" in: "$s"');
        }
      }
    });
  });

  group('strength words', () {
    test('thresholds map to words', () {
      expect(strengthWord(0.9), 'Strong evidence');
      expect(strengthWord(0.7), 'Moderate evidence');
      expect(strengthWord(0.4), 'Early sign');
    });
  });
}
