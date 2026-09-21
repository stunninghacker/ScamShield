import 'package:flutter_test/flutter_test.dart';
import 'package:scamshield/data/demo_samples.dart';
import 'package:scamshield/llm/prompt_template.dart';
import 'package:scamshield/models/scan_result.dart';
import 'package:scamshield/rules/constants.dart';
import 'package:scamshield/rules/scam_engine.dart';
import 'package:scamshield/rules/signals.dart';

void main() {
  const engine = ScamEngine();

  group('LINK_RISK', () {
    test('detects plain https URL', () {
      final m = detectLinks('visit https://delivery-update.com/track?id=1 now');
      expect(m, isNotEmpty);
      expect(m.first.id, 'LINK_RISK');
      // offsets are exact
      expect('visit https://delivery-update.com/track?id=1 now'
          .substring(m.first.start, m.first.end), m.first.matchedText);
    });
    test('boosts shortener', () {
      final plain = detectLinks('see https://example.com/x').first.weight;
      final short = detectLinks('see http://bit.ly/kbc-win2024').first.weight;
      expect(short, greaterThan(plain));
      expect(short, greaterThanOrEqualTo(
          RuleWeights.linkBase + RuleWeights.linkShortener));
    });
    test('boosts http + lookalike bank domain', () {
      final m = detectLinks('go http://sbi-verify.xyz/kyc-update').first;
      expect(m.detail, contains('lookalike'));
      expect(m.detail, contains('no-https'));
      expect(m.weight,
          greaterThanOrEqualTo(RuleWeights.linkBase + RuleWeights.linkLookalike));
    });
    test('flags IP host URLs', () {
      final m = detectLinks('open http://192.168.1.10/login').first;
      expect(m.detail, contains('ip-host'));
    });
    test('no false positive on genuine alert (no URL)', () {
      expect(detectLinks(demoSamples[3].text), isEmpty);
    });
  });

  group('SECRET_REQUEST', () {
    test('OTP', () {
      expect(detectSecretRequest('share your OTP now'), isNotEmpty);
    });
    test('UPI PIN / ATM PIN / CVV / password', () {
      expect(detectSecretRequest('enter your UPI PIN'), isNotEmpty);
      expect(detectSecretRequest('enter ATM PIN'), isNotEmpty);
      expect(detectSecretRequest('share CVV number'), isNotEmpty);
      expect(detectSecretRequest('enter your password'), isNotEmpty);
    });
    test('exact offsets', () {
      const t = 'Do not share your OTP with anyone';
      final m = detectSecretRequest(t).first;
      expect(t.substring(m.start, m.end).toLowerCase(), contains('otp'));
      expect(m.matchedText, t.substring(m.start, m.end));
    });
    test('genuine alert has no secret request', () {
      expect(detectSecretRequest(demoSamples[3].text), isEmpty);
    });
  });

  group('URGENCY_THREAT', () {
    test('blocked / within 24 hours / immediately / last warning', () {
      expect(detectUrgency('account will be BLOCKED'), isNotEmpty);
      expect(detectUrgency('within 24 hours'), isNotEmpty);
      expect(detectUrgency('verify immediately'), isNotEmpty);
      expect(detectUrgency('last warning, legal action'), isNotEmpty);
    });
    test('genuine alert has no urgency', () {
      expect(detectUrgency(demoSamples[3].text), isEmpty);
    });
  });

  group('REWARD_LURE', () {
    test('lottery / won / cashback / claim prize / KBC', () {
      expect(detectReward('You won lottery Rs 10 lakh'), isNotEmpty);
      expect(detectReward('claim your prize now'), isNotEmpty);
      expect(detectReward('cashback of Rs 500'), isNotEmpty);
      expect(detectReward('You won KBC lottery'), isNotEmpty);
      expect(detectReward('refund pending, claim now'), isNotEmpty);
    });
  });

  group('PAYMENT_PULL', () {
    test('UPI handle', () {
      final m = detectPaymentPull('pay to winner-claim@okhdfcbank now');
      expect(m, isNotEmpty);
      expect(m.first.matchedText, contains('@okhdfcbank'));
    });
    test('scan QR / processing fee', () {
      expect(detectPaymentPull('scan this QR to pay'), isNotEmpty);
      expect(detectPaymentPull('pay Rs.499 processing fee'), isNotEmpty);
    });
  });

  group('CALLBACK', () {
    test('phone + call cue fires', () {
      expect(detectCallback('call 9876543210 now'), isNotEmpty);
      expect(detectCallback('Call 1800123456 for help'), isNotEmpty);
    });
    test('phone without call cue does NOT fire (avoid FP)', () {
      expect(detectCallback('my number is 9876543210'), isEmpty);
    });
    test('genuine alert amounts are not phones', () {
      expect(detectCallback(demoSamples[3].text), isEmpty);
    });
  });

  group('IMPERSONATION (composite)', () {
    test('fires only with another signal present', () {
      const genuine = 'Rs.12,450 credited to your SBI A/c XX1234. -SBI';
      expect(detectImpersonation(genuine, otherSignalsNonEmpty: false), isEmpty);
      expect(detectImpersonation(genuine, otherSignalsNonEmpty: true), isNotEmpty);
    });
    test('courier + link counts as impersonation', () {
      final others = detectLinks(demoSamples[2].text);
      expect(others, isNotEmpty);
      expect(
          detectImpersonation(demoSamples[2].text,
              otherSignalsNonEmpty: others.isNotEmpty),
          isNotEmpty);
    });
  });

  group('ENGINE verdicts (demo contract)', () {
    test('sample1 KYC phishing -> DANGEROUS', () {
      final r = engine.analyze(demoSamples[0].text);
      expect(r.verdict, Verdict.dangerous);
      expect(r.score, greaterThanOrEqualTo(RuleThresholds.dangerous));
      expect(r.signals.map((s) => s.id),
          containsAll(['LINK_RISK', 'SECRET_REQUEST', 'URGENCY_THREAT', 'IMPERSONATION']));
    });
    test('sample2 lottery lure -> DANGEROUS', () {
      final r = engine.analyze(demoSamples[1].text);
      expect(r.verdict, Verdict.dangerous);
      expect(r.signals.map((s) => s.id),
          containsAll(['REWARD_LURE', 'PAYMENT_PULL', 'LINK_RISK']));
    });
    test('sample3 courier borderline -> SUSPICIOUS', () {
      final r = engine.analyze(demoSamples[2].text);
      expect(r.verdict, Verdict.suspicious);
      expect(r.score, greaterThanOrEqualTo(RuleThresholds.suspicious));
      expect(r.score, lessThan(RuleThresholds.dangerous));
    });
    test('sample4 genuine alert -> SAFE (the trust moment)', () {
      final r = engine.analyze(demoSamples[3].text);
      expect(r.verdict, Verdict.safe);
      expect(r.signals, isEmpty);
      expect(r.score, 0);
    });
    test('empty input -> SAFE', () {
      final r = engine.analyze('   ');
      expect(r.verdict, Verdict.safe);
      expect(r.score, 0);
    });
    test('all spans exactly match source substrings', () {
      for (final d in demoSamples) {
        final r = engine.analyze(d.text);
        for (final s in r.signals) {
          expect(d.text.substring(s.start, s.end), s.matchedText,
              reason: '${d.title} :: ${s.id} span mismatch');
        }
      }
    });
  });

  group('LLM grounding (prompt + fallback)', () {
    test('prompt embeds verdict + only fired signals', () {
      final r = engine.analyze(demoSamples[0].text);
      final p = PromptTemplate.build(
          message: demoSamples[0].text,
          signals: r.signals,
          verdict: r.verdict,
          score: r.score);
      expect(p, contains('DANGEROUS'));
      for (final s in r.signals) {
        expect(p, contains(s.matchedText));
      }
    });
    test('fallback for SAFE never manufactures threats', () {
      final fb = PromptTemplate.fallback(signals: const [], verdict: Verdict.safe);
      final low = fb.explanation.toLowerCase();
      expect(low, contains('genuine'));
      expect(low.contains('scam') && low.contains('this is a scam'), isFalse);
      expect(fb.whatToDo.toLowerCase(), contains('never share'));
    });
    test('fallback mentions only fired classes', () {
      final r = engine.analyze(demoSamples[3].text);
      final fb = PromptTemplate.fallback(signals: r.signals, verdict: r.verdict);
      expect(fb.explanation, contains('genuine'));
    });
  });
}
