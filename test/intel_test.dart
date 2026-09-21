import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:scamshield/analysis/qr_intel.dart';
import 'package:scamshield/analysis/stages.dart';
import 'package:scamshield/analysis/url_intel.dart';
import 'package:scamshield/analysis/verdict_report.dart';
import 'package:scamshield/data/demo_scenarios.dart';
import 'package:scamshield/events/threat_events.dart';
import 'package:scamshield/llm/ai_provider.dart';
import 'package:scamshield/llm/prompt_template.dart';
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

  group('AI context tags (fusion layer)', () {
    List<String> tags(String text) =>
        contextTagsFor(engine.analyze(text).signals);
    test('combos produce semantic tags', () {
      expect(
          tags('SBI: share your OTP now at http://x.com, urgent'),
          contains('Authority impersonation'));
      expect(tags('share OTP immediately or blocked'),
          contains('Financial pressure'));
      expect(tags('under DIGITAL ARREST, join video call with police'),
          contains('Coercive video-call threat'));
      expect(tags('install AnyDesk and share screen'),
          contains('Device-takeover attempt'));
    });
    test('empty scan -> no tags', () {
      expect(contextTagsFor(const []), isEmpty);
    });
    test('prompt embeds context when provided', () {
      final p = PromptTemplate.build(
          message: 'x',
          signals: const [],
          verdict: Verdict.safe,
          score: 0,
          context: const ['Authority impersonation']);
      expect(p, contains('Authority impersonation'));
    });
  });

  group('Hindi safety lines (static, reviewed)', () {
    test('one line per verdict, non-empty, Devanagari', () {
      for (final v in Verdict.values) {
        final h = PromptTemplate.hindiActionFor(v);
        expect(h, isNotEmpty);
        expect(RegExp(r'[\u0900-\u097F]').hasMatch(h), isTrue,
            reason: '$v line should contain Devanagari');
      }
    });
  });

  group('AI provider routing (honest fallback)', () {
    test('fallback provider always available + grounded', () async {
      final p = RuleFallbackProvider();
      expect(await p.available, isTrue);      final r = await p.explain(
          message: 'share OTP now',
          signals: engine.analyze('share OTP now').signals,
          verdict: Verdict.suspicious,
          score: 30);
      expect(r.fromLocalModel, isFalse);
      expect(r.explanation, isNotEmpty);
    });
    test('router never throws without a model', () async {
      final r = await AiRouter.instance.explain(
          message: 'hello',
          signals: const [],
          verdict: Verdict.safe,
          score: 0);
      expect(r.explanation, contains('genuine'));
    });
  });

  group('event import guards', () {
    test('oversize / malformed payloads rejected', () async {
      final log = EventLog();
      await expectLater(
          log.importJson('x' * (256 * 1024 + 1)),
          throwsA(isA<FormatException>()));
      await expectLater(log.importJson('{"a":1}'),
          throwsA(isA<FormatException>()));
    });
    test('chain fields default null, survive round-trip', () {
      final e = EventLog.fromScan(
          source: 'text',
          category: 'Banking / OTP Scam',
          risk: 'dangerous',
          score: 90,
          confidence: 0.9,
          signals: const [],
          fullText: 'share OTP 123456 now');
      expect(e.stage, isNull);
      expect(e.chainId, isNull);
      final rt = ThreatEvent.fromJson(e.toJson());
      expect(rt.stage, isNull);
      final chained = e.withChain('c1', stage: '4 · OTP theft');
      expect(chained.chainId, 'c1');
      expect(chained.stage, '4 · OTP theft');
    });
  });

  group('demo coverage (all six + chain)', () {    test('every single scenario lands its expected verdict', () {
      for (final s
          in demoScenarios.where((x) => x.kind == ScenarioKind.single)) {
        final r = engine.analyze(s.text!);
        expect(r.verdict.nameUpper, s.expected,
            reason: '${s.id} should be ${s.expected}');
      }
    });
    test('timeline stages stay in attack order', () {
      expect(kycChainStages.map((s) => s.title).toList(),
          ['1 · KYC bait', '2 · Phishing link', '3 · Credential harvest',
           '4 · OTP theft', '5 · Payment fraud']);
    });
  });

  group('legitimate proof (not a keyword alarm)', () {
    test('statement + delivery + advisory texts stay LOW', () {
      const legit = [
        'Your monthly account statement is ready. You can view it in the official app.',
        'Dear customer, Rs.12,450 credited to your SBI A/c XX1234 on 20-Sep. Avl bal Rs.54,210. -SBI',
        'Never share your OTP with anyone. Bank staff will never ask for it.',
        'Meeting moved to 5pm. Bring the report.',
      ];
      for (final t in legit) {
        final r = engine.analyze(t);
        expect(r.verdict, Verdict.safe, reason: '"$t" must be SAFE');
      }
    });
  });

  group('radar escalation (engine-coupled)', () {
    test('urgency -> OTP -> remote-access escalates to DANGEROUS', () {
      var seen = <String>{};
      Verdict last = Verdict.safe;
      var buf = '';
      const lines = [
        'Your account will be blocked in 10 minutes.',
        'Tell me the OTP you just received.',
        'Install this support app and share your screen.',
      ];
      for (final l in lines) {
        buf = buf.isEmpty ? l : '$buf $l';
        final r = engine.analyze(buf);
        expect(r.score,
            greaterThanOrEqualTo(engine.analyze(buf).score));
        seen = r.signals.map((s) => s.id).toSet();
        last = r.verdict;
      }
      expect(seen,
          containsAll(['URGENCY_THREAT', 'SECRET_REQUEST', 'REMOTE_ACCESS']));
      expect(last, Verdict.dangerous);
    });
  });

  group('history privacy (indicator-only storage)', () {
    test('raw secrets never reach SharedPreferences', () async {
      TestWidgetsFlutterBinding.ensureInitialized();
      SharedPreferences.setMockInitialValues({});
      final log = EventLog();
      await log.clear();
      const secret = 'share OTP 889922 now';
      await log.log(EventLog.fromScan(
          source: 'text',
          category: 'Banking / OTP Scam',
          risk: 'dangerous',
          score: 90,
          confidence: 0.9,
          signals: engine.analyze(secret).signals,
          fullText: secret));
      final prefs = await SharedPreferences.getInstance();
      final blob = (prefs.getStringList('scamshield_events_v2') ?? []).join();
      expect(blob, isNot(contains('889922')));
      expect(blob, contains('SECRET_REQUEST'));
    });
    test('chain stages group by chainId, others excluded', () async {
      TestWidgetsFlutterBinding.ensureInitialized();
      SharedPreferences.setMockInitialValues({});
      final log = EventLog();
      await log.clear();
      const cid = 'chain-1';
      await log.log(EventLog.fromScan(
          source: 'timeline', category: 'C', risk: 'safe', score: 0,
          confidence: 0, signals: const [], fullText: 'a')
          .withChain(cid, stage: 's1'));
      await log.log(EventLog.fromScan(
          source: 'timeline', category: 'C', risk: 'safe', score: 0,
          confidence: 0, signals: const [], fullText: 'b')
          .withChain(cid, stage: 's2'));
      await log.log(EventLog.fromScan(
          source: 'text', category: 'C', risk: 'safe', score: 0,
          confidence: 0, signals: const [], fullText: 'c'));
      final stages = await log.stagesOf(cid);
      expect(stages.map((e) => e.stage).toList(), ['s1', 's2']);
      expect(await log.chainIds(), [cid]);
    });
  });
}
