import 'package:flutter_test/flutter_test.dart';
import 'package:scamshield/analysis/attack_chain.dart';
import 'package:scamshield/data/demo_scenarios.dart';
import 'package:scamshield/events/threat_events.dart';
import 'package:scamshield/rules/scam_engine.dart';

void main() {
  const engine = ScamEngine();

  SignalChain chainOf(String text) {
    final r = engine.analyze(text);
    return buildSignalChain(
      signals: r.signals,
      breakdown: r.breakdown,
      verdict: r.verdict,
      score: r.score,
    );
  }

  group('ScamFamily — every family fires', () {
    test('phishing: bare suspicious link', () {
      expect(chainOf('Update your details here: https://example.com/verify')
          .family, ScamFamily.phishing);
    });
    test('bankingFraud: OTP pressure', () {
      expect(
          chainOf('SBI: share your OTP now, account blocked').family,
          ScamFamily.bankingFraud);
    });
    test('digitalArrest: coercive call threat', () {
      expect(
          chainOf('You are under DIGITAL ARREST by CBI. Join video call now.')
              .family,
          ScamFamily.digitalArrest);
    });
    test('jobScam: part-time lure', () {
      expect(
          chainOf('PART-TIME JOB from home. Earn Rs.5,000 per day on '
                  'Telegram tasks.')
              .family,
          ScamFamily.jobScam);
    });
    test('remoteAccess: support-app trap', () {
      expect(
          chainOf('Install AnyDesk and share your screen for support.')
              .family,
          ScamFamily.remoteAccess);
    });
    test('deliveryScam: courier + link + callback', () {
      expect(
          chainOf('Delhivery courier: your parcel is held. Track '
                  'http://bit.ly/dl44 or call 98765 43210.')
              .family,
          ScamFamily.deliveryScam);
    });
    test('investmentScam: crypto profits + UPI payee', () {
      expect(
          chainOf('Invest Rs.10,000 in crypto trading. Guaranteed 3x '
                  'profits in 7 days. Pay to profit@okhdfcbank now.')
              .family,
          ScamFamily.investmentScam);
    });
    test('accountTakeover: password harvest via link', () {
      expect(
          chainOf('SBI alert: verify your account now at '
                  'http://sbi-verify.xyz/login. Enter your password '
                  'to continue.')
              .family,
          ScamFamily.accountTakeover);
    });
    test('none: genuine message', () {
      final c = chainOf('Meeting moved to 5pm. Bring the report.');
      expect(c.family, ScamFamily.none);
      expect(c.steps, isEmpty);
    });
  });

  group('adversarial combinations (priority order)', () {
    test('digital arrest outranks job lure', () {
      expect(
          chainOf('PART-TIME JOB offer. You are under DIGITAL ARREST '
                  'by CBI, pay the fine now.')
              .family,
          ScamFamily.digitalArrest);
    });
    test('remote access outranks prize lure', () {
      expect(
          chainOf('You won a prize! Install AnyDesk to claim it.')
              .family,
          ScamFamily.remoteAccess);
    });
    test('secret + remote = account takeover, not remote access', () {
      expect(
          chainOf('Share your screen on AnyDesk and tell me the OTP now.')
              .family,
          ScamFamily.accountTakeover);
    });
    test('payment-only (no lure) is banking fraud', () {
      expect(
          chainOf('Pay Rs.500 to shop@okhdfcbank for your order.').family,
          ScamFamily.bankingFraud);
    });
    test('secret without urgency or link is account takeover', () {
      expect(
          chainOf('Enter your PAN, account number and ATM PIN to verify.')
              .family,
          ScamFamily.accountTakeover);
    });
    test('negation preserved: advisory text has no signals, no family',
        () {
      final c =
          chainOf('Never share your OTP with anyone. Bank staff will '
              'never ask for it.');
      expect(c.family, ScamFamily.none);
      expect(c.steps, isEmpty);
    });
  });

  group('no duplicate contributions', () {
    test('repeated keywords collapse to one signal, weight counted once',
        () {
      final c = chainOf(
          'winner winner winner! You won, winner! Claim prize now');
      final rewards =
          c.steps.where((s) => s.signal.id == 'REWARD_LURE');
      expect(rewards, hasLength(1));
      expect(rewards.single.signal.contribution,
          engine.analyze('winner').breakdown['REWARD_LURE']);
      // Extra spans raise strength, never the contribution.
      final single = chainOf('winner!');
      expect(
          rewards.single.signal.strength,
          greaterThanOrEqualTo(single.steps
              .singleWhere((s) => s.signal.id == 'REWARD_LURE')
              .signal
              .strength));
    });
    test('every class appears once; contributions sum to raw score', () {
      for (final s
          in demoScenarios.where((x) => x.kind == ScenarioKind.single)) {
        final c = chainOf(s.text!);
        final ids = c.steps.map((x) => x.signal.id).toList();
        expect(ids.toSet(), hasLength(ids.length),
            reason: '${s.id}: duplicate signal $ids');
        final raw = c.steps
            .fold<int>(0, (a, x) => a + x.signal.contribution);
        final r = engine.analyze(s.text!);
        final expected = r.breakdown.values
            .fold<int>(0, (a, v) => a + v);
        expect(raw, expected, reason: '${s.id}: contribution mismatch');
      }
    });
  });

  group('evidence spans + strength', () {
    test('every signal carries id, label, spans, contribution, strength',
        () {
      final c = chainOf(demoScenarios
          .firstWhere((s) => s.id == 'kyc')
          .text!);
      expect(c.steps, isNotEmpty);
      for (final st in c.steps) {
        final d = st.signal;
        expect(d.id, isNotEmpty);
        expect(d.label, isNotEmpty);
        expect(d.evidence, isNotEmpty);
        expect(d.contribution, greaterThan(0));
        expect(d.strength, inInclusiveRange(0.0, 0.95));
        expect(d.start, lessThanOrEqualTo(d.end));
      }
    });
    test('lookalike link outranks a plain link', () {
      final evil = buildEvidence(
          engine
              .analyze('verify at http://sbi-verify.xyz/login now')
              .signals,
          engine
              .analyze('verify at http://sbi-verify.xyz/login now')
              .breakdown);
      final plain = buildEvidence(
          engine.analyze('see https://example.com/info').signals,
          engine.analyze('see https://example.com/info').breakdown);
      expect(
          evil.singleWhere((d) => d.id == 'LINK_RISK').strength,
          greaterThan(
              plain.singleWhere((d) => d.id == 'LINK_RISK').strength));
    });
    test('strength never claims certainty', () {
      final c = chainOf(radarArrestScript.map((l) => l.text).join(' '));
      for (final st in c.steps) {
        expect(st.signal.strength, lessThan(1.0));
      }
    });
  });

  group('ordered attack chain', () {
    test('steps follow canonical order, not text order', () {
      final c = chainOf('Pay Rs.500 to shop@okhdfcbank now. SBI says '
          'share your OTP at http://example.com/a immediately or '
          'blocked!');
      final ids = c.steps.map((s) => s.signal.id).toList();
      expect(
          ids,
          orderedEquals([
            'IMPERSONATION',
            'URGENCY_THREAT',
            'LINK_RISK',
            'SECRET_REQUEST',
            'PAYMENT_PULL',
          ]));
      expect(
          c.steps.map((s) => s.stage).toList(),
          orderedEquals(
              ['Trust', 'Pressure', 'Vector', 'Harvest', 'Cash-out']));
    });
    test('chain mirrors the engine verdict and score', () {
      for (final s
          in demoScenarios.where((x) => x.kind == ScenarioKind.single)) {
        final r = engine.analyze(s.text!);
        final c = chainOf(s.text!);
        expect(c.verdict, r.verdict, reason: s.id);
        expect(c.score, r.score, reason: s.id);
      }
    });
  });

  group('serialization (Timeline + Command Center)', () {
    test('SignalChain round-trips through JSON', () {
      final c = chainOf(demoScenarios
          .firstWhere((s) => s.id == 'kyc')
          .text!);
      final j = c.toJson();
      expect(j['family'], 'bankingFraud');
      expect(j['familyLabel'], 'Banking fraud');
      expect(j['verdict'], 'dangerous');
      expect((j['steps'] as List), isNotEmpty);
      final first =
          (j['steps'] as List).first as Map<String, dynamic>;
      expect(first['stage'], 'Trust');
      final rt = DetectedSignal.fromJson(
          Map<String, dynamic>.from(first));
      expect(rt.id, first['id']);
      expect(rt.evidence, isNotEmpty);
    });
    test('ThreatEvent carries family, defaults empty for legacy', () {
      final e = EventLog.fromScan(
          source: 'text',
          category: 'Banking / OTP Scam',
          risk: 'dangerous',
          score: 90,
          confidence: 0.9,
          signals: const [],
          fullText: 'x',
          family: 'Banking fraud');
      expect(e.family, 'Banking fraud');
      expect(
          ThreatEvent.fromJson(e.toJson()).family, 'Banking fraud');
      expect(
          ThreatEvent.fromJson(const <String, dynamic>{}).family, '');
    });
  });
}
