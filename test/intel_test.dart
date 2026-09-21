import 'package:flutter_test/flutter_test.dart';
import 'package:scamshield/analysis/qr_intel.dart';
import 'package:scamshield/analysis/stages.dart';
import 'package:scamshield/analysis/url_intel.dart';
import 'package:scamshield/analysis/verdict_report.dart';
import 'package:scamshield/data/demo_scenarios.dart';
import 'package:scamshield/events/threat_events.dart';
import 'package:scamshield/models/verdict.dart';
import 'package:scamshield/rules/scam_engine.dart';
import 'package:scamshield/rules/signals.dart';

void main() {
  const engine = ScamEngine();

  group('REMOTE_ACCESS', () {
    test('AnyDesk / screen share / apk', () {
      expect(detectRemoteAccess('install AnyDesk now'), isNotEmpty);
      expect(
          detectRemoteAccess('please share your screen'), isNotEmpty);
      expect(
          detectRemoteAccess('download this apk file'), isNotEmpty);
    });
    test('no FP on v1 samples', () {
      for (final d in demoScenarios.where((s) => s.text != null)) {
        expect(detectRemoteAccess(d.text!), isEmpty,
            reason: '${d.id} should not fire REMOTE_ACCESS');
      }
    });
  });

  group('JOB_LURE', () {
    test('part-time / earn / telegram tasks', () {
      expect(detectJobLure('PART-TIME JOB from home'), isNotEmpty);
      expect(detectJobLure('Earn Rs.5,000 per day'), isNotEmpty);
      expect(detectJobLure('tasks on Telegram, commission'), isNotEmpty);
    });
    test('job scenario -> DANGEROUS', () {
      final t = demoScenarios.firstWhere((s) => s.id == 'job').text!;
      final r = engine.analyze(t);
      expect(r.verdict, Verdict.dangerous);
      expect(r.signals.map((s) => s.id), contains('JOB_LURE'));
    });
  });

  group('DIGITAL_ARREST', () {
    test('digital arrest / video call / parcel drugs', () {
      expect(detectDigitalArrest('You are under DIGITAL ARREST'),
          isNotEmpty);
      expect(
          detectDigitalArrest('join video call with police'), isNotEmpty);
      expect(detectDigitalArrest('parcel caught with narcotics'),
          isNotEmpty);
    });
    test('otp scenario -> DANGEROUS with SECRET+LINK', () {
      final t = demoScenarios.firstWhere((s) => s.id == 'otp').text!;
      final r = engine.analyze(t);
      expect(r.verdict, Verdict.dangerous);
      expect(r.signals.map((s) => s.id),
          containsAll(['SECRET_REQUEST', 'LINK_RISK']));
    });
    test('arrest radar transcript -> DANGEROUS', () {
      final full = radarArrestScript.map((l) => l.text).join(' ');
      final r = engine.analyze(full);
      expect(r.verdict, Verdict.dangerous);
      expect(r.signals.map((s) => s.id), contains('DIGITAL_ARREST'));
    });
  });

  group('breakdown sums to score', () {
    test('contributions add up and carry labels', () {
      final r = engine.analyze(demoScenarios
          .firstWhere((s) => s.id == 'kyc')
          .text!);
      final parts = contributionsFor(r.breakdown);
      expect(parts, isNotEmpty);
      // Breakdown holds raw per-class weights; score is the sum clamped.
      final raw =
          parts.fold<int>(0, (a, p) => a + p.weight);
      expect(r.score, raw > 100 ? 100 : raw);
      expect(r.breakdown['LINK_RISK'], lessThanOrEqualTo(60)); // cap
      expect(parts.first.weight,
          greaterThanOrEqualTo(parts.last.weight)); // sorted
    });
  });

  group('category + confidence', () {
    test('categories', () {
      String cat(String text) =>
          categoryFor(engine.analyze(text).signals);
      expect(cat('share your OTP now, account blocked'),
          'Banking / OTP Scam');
      expect(cat('You won lottery, pay fee to claim'), anyOf(
          'Lottery / Refund Scam', 'Payment Scam'));
      expect(cat('under DIGITAL ARREST by CBI, video call now'),
          'Digital Arrest');
      expect(cat('part-time job earn Rs.5000 per day'), 'Job / Task Scam');
      expect(categoryFor(const []), 'Genuine');
    });
    test('confidence is heuristic, never 1.0', () {
      expect(confidenceFor(0, hasSignals: false), 0.0);
      final c = confidenceFor(100, hasSignals: true);
      expect(c, greaterThan(0.5));
      expect(c, lessThan(1.0));
      expect(confidenceFor(55, hasSignals: true),
          lessThan(confidenceFor(100, hasSignals: true)));
    });
  });

  group('URL intelligence', () {
    test('legit domain -> low', () {
      final r = analyzeUrl('https://www.onlinesbi.com/personal');
      expect(r.valid, isTrue);
      expect(r.isHttps, isTrue);
      expect(r.risk, 'low');
    });
    test('lookalike bank -> high', () {
      final r = analyzeUrl('http://sbi-verify.xyz/kyc-update');
      expect(r.risk, 'high');
      expect(r.isLookalike, isTrue);
      expect(r.brandHits, contains('sbi'));
      expect(r.credentialPath, isTrue);
      expect(r.isHttps, isFalse);
    });
    test('IP URL -> finding', () {
      final r = analyzeUrl('http://192.168.1.10/login');
      expect(r.isIp, isTrue);
      expect(r.findings.map((f) => f.label), contains('IP-address host'));
    });
    test('shortener -> medium+', () {
      final r = analyzeUrl('http://bit.ly/kbc-win2024');
      expect(r.isShortener, isTrue);
      expect(r.risk, anyOf('medium', 'high'));
    });
    test('punycode flagged', () {
      final r = analyzeUrl('https://xn--sbi-bank.com/login');
      expect(r.isPunycode, isTrue);
    });
    test('malformed -> invalid, never throws', () {
      expect(analyzeUrl('not a url at all!!').valid, isFalse);
      expect(analyzeUrl('').valid, isFalse);
    });
    test('offline-unavailable list is honest', () {
      expect(UrlReport.unavailable.join(' '), contains('Redirect'));
    });
  });

  group('QR intelligence', () {
    test('upi pay -> payment request with payee', () {
      final r = analyzeQr('upi://pay?pa=scammer@okhdfcbank&pn=Shop&am=499');
      expect(r.kind, QrKind.upiPayment);
      expect(r.upiPayee, 'scammer@okhdfcbank');
      expect(r.upiAmount, '499');
      expect(r.note, contains('SEND'));
    });
    test('upi without payee -> suspicious', () {
      final r = analyzeQr('upi://pay?am=100');
      expect(r.note, contains('no payee'));
    });
    test('malicious URL QR inherits url risk', () {
      final r = analyzeQr('http://sbi-verify.xyz/kyc');
      expect(r.kind, QrKind.url);
      expect(r.urlReport!.risk, 'high');
    });
    test('contact / wifi / text / empty', () {
      expect(analyzeQr('BEGIN:VCARD\nFN:Bob').kind, QrKind.contact);
      expect(analyzeQr('WIFI:S:Home;T:WPA;P:1234;;').kind, QrKind.wifi);
      expect(analyzeQr('hello world').kind, QrKind.text);
      expect(analyzeQr('   ').kind, QrKind.invalid);
    });
  });

  group('attack chains', () {
    test('KYC chain is a real chain, worst=DANGEROUS', () {
      final chain = buildChain(kycChainStages);
      expect(chain.isChain, isTrue);
      expect(chain.verdict, Verdict.dangerous);
      expect(chain.stagesFlagged, greaterThanOrEqualTo(2));
      expect(chain.maxScore, greaterThanOrEqualTo(60));
    });
    test('single bad message among clean ones is NOT a chain', () {
      final chain = buildChain(const [
        StageInput('a', 'Dear customer, balance Rs.1,000. -SBI'),
        StageInput('b', 'Meeting at 5pm tomorrow.'),
        StageInput('c', 'Your SBI KYC expired, share OTP now'),
      ]);
      expect(chain.isChain, isFalse);
    });
  });

  group('redaction', () {
    test('digit runs masked, text kept', () {
      final p = redactPreview('Rs.12,450 credited to A/c 123456 OTP 8899');
      expect(p, isNot(contains('123456')));
      expect(p, contains('credited'));
    });
  });
}
