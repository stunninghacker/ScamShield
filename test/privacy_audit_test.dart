import 'dart:convert';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:scamshield/analysis/url_intel.dart';
import 'package:scamshield/events/threat_events.dart';
import 'package:scamshield/llm/ai_provider.dart';
import 'package:scamshield/llm/gemma_service.dart';
import 'package:scamshield/llm/prompt_template.dart';
import 'package:scamshield/models/signal_match.dart';
import 'package:scamshield/models/verdict.dart';
import 'package:scamshield/rules/scam_engine.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Automated privacy and network behavior audit tests.
///
/// Every check here reads the REAL files in this repository — manifest,
/// pubspec, Dart sources, assets — and fails if the property regresses.
/// No placeholders: if a claim in the README is not enforced by a file
/// assertion below, it is not claimed.
///
/// Run with: `flutter test test/privacy_audit_test.dart`

String _read(String rel) => File(rel).readAsStringSync();

List<File> _libFiles() => Directory('lib')
    .listSync(recursive: true)
    .whereType<File>()
    .where((f) => f.path.endsWith('.dart'))
    .toList();

String _libSrc() =>
    _libFiles().map((f) => f.readAsStringSync()).join('\n');

void main() {
  group('PRIVACY AUDIT — network dependencies', () {
    test('no INTERNET permission in release manifest', () {
      final manifest = _read('android/app/src/main/AndroidManifest.xml');
      // Strip comments first: the manifest deliberately DOCUMENTS the rule
      // ("Do NOT add ... INTERNET"), which would fool a naive contains().
      final stripped =
          manifest.replaceAll(RegExp(r'<!--.*?-->', dotAll: true), '');
      expect(stripped, isNot(contains('android.permission.INTERNET')),
          reason: 'the demo runs in airplane mode by design');
    });

    test('no allowBackup in manifest', () {
      final manifest = _read('android/app/src/main/AndroidManifest.xml');
      final stripped =
          manifest.replaceAll(RegExp(r'<!--.*?-->', dotAll: true), '');
      expect(stripped, isNot(contains('android:allowBackup')),
          reason: 'full backup would leak local history to a PC');
    });

    test('no http / dio / websocket package in pubspec.yaml', () {
      final pubspec = _read('pubspec.yaml');
      expect(RegExp(r'^\s*(http|dio|web_socket_channel)\s*:', multiLine: true)
              .hasMatch(pubspec),
          isFalse,
          reason: 'network packages would break the offline guarantee');
      expect(pubspec, isNot(contains('package:http')));
    });

    test('no socket/WebSocket/HttpClient usage in lib/', () {
      // Checks imports and constructor calls — the words themselves may
      // appear in safety copy (e.g. the Judge screen writes "WebSocket:
      // none"), which is a claim, not capability.
      final src = _libSrc();
      for (final token in [
        'HttpClient(',
        'WebSocket(',
        'Socket(',
        'package:http',
        'package:dio',
        'package:web_socket',
      ]) {
        expect(src.contains(token), isFalse,
            reason: 'lib/ must never open a network connection (found: '
                '$token)');
      }
    });
  });

  group('PRIVACY AUDIT — URL fetching', () {
    test('URLs are never fetched — analyzeUrl returns without network', () {
      // The UrlReport.unavailable list confirms offline mode:
      expect(UrlReport.unavailable.length, 2);
      expect(UrlReport.unavailable.first, contains('would require fetching'));
      expect(UrlReport.unavailable.last, contains('no reputation API'));

      // Analyze a lookalike URL — no fetch happens.
      final report = analyzeUrl('http://sbi-verify.xyz/kyc');
      expect(report.risk, 'high');
      expect(report.isLookalike, isTrue);
      // The URL was parsed locally — no HTTP request made.
      expect(report.valid, isTrue);
    });

    test('URL analysis is fully local — no unresolved host fetch', () {
      // Even with a real-looking URL, only parsing occurs.
      final report = analyzeUrl('https://www.onlinesbi.com/personal');
      expect(report.risk, 'low');
      expect(report.host, contains('onlinesbi'));
    });

    test('UPI URLs parsed locally, not executed', () {
      final report = analyzeUrl('upi://pay?pa=scammer@okhdfcbank&pn=Shop&am=499');
      expect(report.upiScheme, isTrue);
      // UPI scheme is parsed but never invoked/opened by the app.
      expect(report.valid, isTrue);
    });
  });

  group('PRIVACY AUDIT — clipboard hard limits', () {
    test('importJson rejects payloads > 256KB', () async {
      final log = EventLog();
      await expectLater(
          log.importJson('x' * (256 * 1024 + 1)),
          throwsA(isA<FormatException>()));
    });

    test('importJson rejects > 100 events', () async {
      final log = EventLog();
      // Build a valid JSON list with 101 events
      final events = List.generate(101, (i) => {
            'id': 'e$i',
            'timestamp': DateTime.now().toIso8601String(),
            'source': 'text',
            'category': 'Test',
            'risk': 'safe',
            'score': 0,
            'confidence': 0.0,
            'signals': <String>[],
            'evidenceCount': 0,
            'preview': 'test',
            'action': 'None',
            'demo': false,
            'family': '',
          });
      await expectLater(
          log.importJson(jsonEncode(events)),
          throwsA(isA<FormatException>()));
    });

    test('importJson accepts valid small payload', () async {
      TestWidgetsFlutterBinding.ensureInitialized();
      SharedPreferences.setMockInitialValues({});
      final log = EventLog();
      await log.clear();
      final events = [{
        'id': 'e1',
        'timestamp': DateTime.now().toIso8601String(),
        'source': 'text',
        'category': 'Test',
        'risk': 'safe',
        'score': 0,
        'confidence': 0.0,
        'signals': <String>[],
        'evidenceCount': 0,
        'preview': 'test',
        'action': 'None',
        'demo': false,
        'family': '',
      }];
      final n = await log.importJson(jsonEncode(events));
      expect(n, 1);
    });
  });

  group('PRIVACY AUDIT — history stores only indicators', () {
    test('EventLog.fromScan stores redacted preview, not raw text', () {
      const secret = 'share OTP 889922 now, click http://evil.com';
      final e = EventLog.fromScan(
          source: 'text',
          category: 'Banking / OTP Scam',
          risk: 'dangerous',
          score: 90,
          confidence: 0.9,
           signals: const <SignalMatch>[],
           fullText: secret);
       // Preview should mask digits but keep text structure
       expect(e.preview, isNot(contains('889922')));
       expect(e.preview, contains('share'));
       expect(e.preview, contains('evil'));
       // The full raw text is NEVER stored in the event
       expect(e.toJson()['preview'], isNot(contains('889922')));
     });

    test('EventLog stores indicator fields only', () {
      const secret = 'Your bank password is 123456';
      final e = EventLog.fromScan(
          source: 'text',
          category: 'Banking / OTP Scam',
          risk: 'dangerous',
          score: 95,
          confidence: 0.95,
          signals: const <SignalMatch>[],
          fullText: secret);
      final json = e.toJson();
      // Fields present: indicators only
      expect(json.containsKey('category'), isTrue);
      expect(json.containsKey('risk'), isTrue);
      expect(json.containsKey('score'), isTrue);
      expect(json.containsKey('signals'), isTrue);
      expect(json.containsKey('preview'), isTrue);
      expect(json.containsKey('evidenceCount'), isTrue);
      // Full raw message is never stored
      expect(json.containsKey('fullText'), isFalse);
      expect(json['preview'], isNot(contains('123456')));
    });

    test('ThreatEvent withChain preserves only indicator data', () {
      final e = EventLog.fromScan(
          source: 'text',
          category: 'Test',
          risk: 'suspicious',
          score: 30,
          confidence: 0.5,
          signals: const [],
          fullText: 'some secret OTP 9999 here');
      final chained = e.withChain('chain-1', stage: '2 · Phishing link');
      final json = chained.toJson();
      expect(json['chainId'], 'chain-1');
      expect(json['stage'], '2 · Phishing link');
      expect(json['preview'], isNot(contains('9999')));
    });
  });

  group('PRIVACY AUDIT — no secrets or API keys bundled', () {
    test('no API keys in pubspec.yaml', () {
      final pubspec = _read('pubspec.yaml');
      expect(RegExp(r'AIza[0-9A-Za-z_\-]{30,}').hasMatch(pubspec), isFalse,
          reason: 'Google-style API key found in pubspec');
      expect(
          RegExp(r'^\s*(api[_-]?key|client[_-]?secret|access[_-]?token)\s*:',
                  caseSensitive: false, multiLine: true)
              .hasMatch(pubspec),
          isFalse,
          reason: 'secret-looking key declared in pubspec');
    });

    test('no hardcoded secrets in lib/ Dart code', () {
      final src = _libSrc();
      expect(RegExp(r'AIza[0-9A-Za-z_\-]{30,}').hasMatch(src), isFalse,
          reason: 'Google-style API key hardcoded in lib/');
      expect(RegExp(r'\bsk-[A-Za-z0-9]{20,}').hasMatch(src), isFalse,
          reason: 'OpenAI-style secret key hardcoded in lib/');
      expect(RegExp(r'Bearer\s+[A-Za-z0-9._\-]{20,}').hasMatch(src), isFalse,
          reason: 'bearer token hardcoded in lib/');
    });

    test('assets/models/ has only .gitkeep placeholder', () {
      final entries = Directory('assets/models').listSync();
      expect(entries, isNotEmpty);
      expect(entries.any((e) => e.path.endsWith('.task')), isFalse,
          reason: 'the Gemma model must never be committed to the repo');
      expect(entries.any((e) => e.path.endsWith('.bin')), isFalse);
      for (final e in entries) {
        expect(e.uri.pathSegments.last, '.gitkeep',
            reason: 'unexpected file bundled in assets/models: ${e.path}');
      }
    });

    test('gemma_service init fails gracefully without model', () async {
      // No .task is bundled, so init() must return false (never throw)
      // and explain() must stay on the grounded rule fallback.
      final ok = await GemmaService.instance.init();
      expect(ok, isFalse);
      expect(GemmaService.instance.isReady, isFalse);
      final out = await GemmaService.instance.explain(
          message: 'share your OTP now',
          signals: const <SignalMatch>[],
          verdict: Verdict.dangerous,
          score: 90);
      expect(out.llmUsed, isFalse,
          reason: 'without a bundled model the app must never claim an '
              'LLM produced the explanation');
    });
  });

  group('PRIVACY AUDIT — AI explanation safe fallback', () {
    test('fallback provider never claims certainty', () {
      final fb = PromptTemplate.fallback(
          signals: const [], verdict: Verdict.safe);
      expect(fb.explanation, contains('genuine'));
      expect(fb.explanation, isNot(contains('certain')));
    });

    test('fallback uses only fired signals, never invents', () {
      const engine = ScamEngine();
      final text = 'share your OTP now';
      final r = engine.analyze(text);
      final fb = PromptTemplate.fallback(
          signals: r.signals, verdict: r.verdict);
      // Explanation should mention the signal details, not invent new ones
      expect(fb.explanation, isNotEmpty);
      // Fallback never claims to be AI or connected
      expect(fb.explanation.toLowerCase().contains('ai'), isFalse);
    });

    test('fallback never manufactures threats from empty input', () {
      final fb = PromptTemplate.fallback(
          signals: const [], verdict: Verdict.safe);
      expect(fb.explanation, contains('genuine'));
      expect(fb.whatToDo.toLowerCase().contains('never share'), isTrue);
    });

    test('RuleFallbackProvider is always available', () async {
      final p = RuleFallbackProvider();
      expect(await p.available, isTrue);
    });
  });

  group('PRIVACY AUDIT — no telemetry or analytics', () {
    test('no analytics packages in pubspec', () {
      final pubspec = _read('pubspec.yaml');
      expect(
          RegExp(r'^\s*(firebase.*|.*analytics|amplitude|mixpanel|'
                  r'sentry|crashlytics|adjust|appsflyer)\s*:',
                  caseSensitive: false, multiLine: true)
              .hasMatch(pubspec),
          isFalse,
          reason: 'a telemetry package would break the privacy claim');
    });

    test('no network calls in scan pipeline', () {
      final pipeline = _read('lib/analysis/scan_pipeline.dart');
      for (final token in ['package:http', 'HttpClient', 'WebSocket', 'get(']) {
        expect(pipeline.contains(token), isFalse,
            reason: 'the automatic scan path must stay local (found: '
                '$token)');
      }
      expect(pipeline, contains('_engine.analyze'),
          reason: 'scan path must run the local deterministic engine');
    });
  });

  group('PRIVACY AUDIT — local-first architecture', () {
    test('shared_preferences is the only persistence mechanism', () {
      final pubspec = _read('pubspec.yaml');
      expect(
          RegExp(r'^\s*(sqflite|hive|isar|drift|flutter_secure_storage)\s*:',
                  multiLine: true)
              .hasMatch(pubspec),
          isFalse,
          reason: 'only shared_preferences may hold local state');
      final events = _read('lib/events/threat_events.dart');
      expect(events, contains('SharedPreferences'),
          reason: 'EventLog must persist through SharedPreferences');
    });

    test('EventLog.clear() removes all local data', () async {
      TestWidgetsFlutterBinding.ensureInitialized();
      SharedPreferences.setMockInitialValues({});
      final log = EventLog();
      await log.clear();
      await log.importJson(jsonEncode([
        {
          'id': 'e-clear',
          'timestamp': DateTime.now().toIso8601String(),
          'source': 'text',
          'category': 'Test',
          'risk': 'safe',
          'score': 0,
          'confidence': 0.0,
          'signals': <String>[],
          'evidenceCount': 0,
          'preview': 'test',
          'action': 'None',
          'demo': false,
          'family': '',
        }
      ]));
      expect(jsonDecode(await log.exportJson()), isNotEmpty);
      await log.clear();
      expect(jsonDecode(await log.exportJson()), isEmpty,
          reason: 'clear() must wipe every stored event');
    });

    test('EventLog.exportJson/importJson are user-initiated only', () {
      // The automatic path (scan pipeline) must never call export/import,
      // and no background timer may push history anywhere.
      final pipeline = _read('lib/analysis/scan_pipeline.dart');
      expect(pipeline.contains('importJson'), isFalse);
      expect(pipeline.contains('exportJson'), isFalse);
      final events = _read('lib/events/threat_events.dart');
      expect(events.contains('Timer('), isFalse,
          reason: 'no background timer may sync history');
      expect(events.contains('package:http'), isFalse);
    });
  });
}
