/// Local threat-event log — the data behind History, Command Center and
/// phone↔desktop sync. Privacy-first (SPEC §11/§25):
///  - stores INDICATORS (category, risk, score, signal ids/count, action),
///  - never the full message: only a redacted preview (digits masked),
///  - on-device only (shared_preferences), deletable, exportable by the user.
library;

import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/signal_match.dart';

/// Masks digit runs (4+) so previews never leak account numbers/OTPs.
String redactPreview(String text, {int maxLen = 90}) {
  var t = text.replaceAll(RegExp(r'\d{4,}'), '••••');
  t = t.replaceAll(RegExp(r'\s+'), ' ').trim();
  return t.length > maxLen ? '${t.substring(0, maxLen)}…' : t;
}

class ThreatEvent {
  final String id; // millis + counter-ish uniqueness
  final String timestamp; // ISO-8601
  final String source; // text | url | qr | image | voice
  final String category; // Banking / OTP Scam, ...
  final String risk; // safe | suspicious | dangerous
  final int score;
  final double confidence;
  final List<String> signals; // signal ids
  final int evidenceCount; // total spans
  final String preview; // redacted
  final String action; // Verify / Block / Report / None
  final bool demo; // true for clearly-labeled demo/sample events
  final String? stage; // attack-chain stage title, if part of a chain
  final String? chainId; // groups stages of one detected chain

  const ThreatEvent({
    required this.id,
    required this.timestamp,
    required this.source,
    required this.category,
    required this.risk,
    required this.score,
    required this.confidence,
    required this.signals,
    required this.evidenceCount,
    required this.preview,
    this.action = 'None',
    this.demo = false,
    this.stage,
    this.chainId,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'timestamp': timestamp,
        'source': source,
        'category': category,
        'risk': risk,
        'score': score,
        'confidence': confidence,
        'signals': signals,
        'evidenceCount': evidenceCount,
        'preview': preview,
        'action': action,
        'demo': demo,
        'stage': stage,
        'chainId': chainId,
      };

  factory ThreatEvent.fromJson(Map<String, dynamic> j) => ThreatEvent(
        id: '${j['id']}',
        timestamp: '${j['timestamp']}',
        source: '${j['source'] ?? 'text'}',
        category: '${j['category'] ?? 'Suspicious Message'}',
        risk: '${j['risk'] ?? 'suspicious'}',
        score: (j['score'] as num?)?.toInt() ?? 0,
        confidence: (j['confidence'] as num?)?.toDouble() ?? 0.0,
        signals: ((j['signals'] as List?) ?? const [])
            .map((e) => '$e')
            .toList(),
        evidenceCount: (j['evidenceCount'] as num?)?.toInt() ?? 0,
        preview: '${j['preview'] ?? ''}',
        action: '${j['action'] ?? 'None'}',
        demo: (j['demo'] ?? false) as bool,
        stage: j['stage'] == null ? null : '${j['stage']}',
        chainId: j['chainId'] == null ? null : '${j['chainId']}',
      );

  /// Copy with attack-chain linkage (used when logging Timeline views).
  ThreatEvent withChain(String chainId, {String? stage}) => ThreatEvent(
        id: id,
        timestamp: timestamp,
        source: source,
        category: category,
        risk: risk,
        score: score,
        confidence: confidence,
        signals: signals,
        evidenceCount: evidenceCount,
        preview: preview,
        action: action,
        demo: demo,
        stage: stage ?? this.stage,
        chainId: chainId,
      );
}

class EventLog {
  static const _key = 'scamshield_events_v2';
  static const maxItems = 100;

  static String newId() =>
      '${DateTime.now().millisecondsSinceEpoch}-${DateTime.now().microsecond % 1000}';

  Future<List<ThreatEvent>> list() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_key) ?? const [];
    final out = <ThreatEvent>[];
    for (final s in raw) {
      try {
        out.add(ThreatEvent.fromJson(
            Map<String, dynamic>.from(jsonDecode(s) as Map)));
      } catch (_) {
        // skip corrupt entries
      }
    }
    return out;
  }

  Future<void> log(ThreatEvent e) async {
    final prefs = await SharedPreferences.getInstance();
    final current = prefs.getStringList(_key) ?? <String>[];
    current.insert(0, jsonEncode(e.toJson()));
    while (current.length > maxItems) {
      current.removeLast();
    }
    await prefs.setStringList(_key, current);
  }

  Future<void> setAction(String id, String action) async {
    final prefs = await SharedPreferences.getInstance();
    final current = prefs.getStringList(_key) ?? <String>[];
    for (var i = 0; i < current.length; i++) {
      try {
        final m = Map<String, dynamic>.from(jsonDecode(current[i]) as Map);
        if ('${m['id']}' == id) {
          m['action'] = action;
          current[i] = jsonEncode(m);
          break;
        }
      } catch (_) {}
    }
    await prefs.setStringList(_key, current);
  }

  Future<void> clear() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_key);
    // Legacy v1 full-text history too (migrated away for privacy).
    await prefs.remove('scamshield_history_v1');
  }

  /// All events of one attack chain, oldest first. Independent scans never
  /// share a chainId, so unrelated events are never merged.
  Future<List<ThreatEvent>> stagesOf(String chainId) async {
    final all = await list();
    // list() is newest-first: reverse to oldest-first, then stable-sort by
    // timestamp so same-millisecond stages keep insertion order.
    final out =
        all.reversed.where((e) => e.chainId == chainId).toList()
          ..sort((a, b) => a.timestamp.compareTo(b.timestamp));
    return out;
  }

  /// Distinct chainIds present, newest chain first.
  Future<List<String>> chainIds() async {
    final all = await list();
    final seen = <String>[];
    for (final e in all) {
      final c = e.chainId;
      if (c != null && !seen.contains(c)) seen.add(c);
    }
    return seen;
  }

  /// Export for phone↔desktop sync (user-initiated, offline, via clipboard).
  Future<String> exportJson() async {
    final items = await list();
    return jsonEncode(items.map((e) => e.toJson()).toList());
  }

  /// Import a previously exported payload. Returns events imported.
  /// Hardened: rejects oversized payloads and caps event count so a
  /// malicious clipboard payload cannot blow up local storage.
  Future<int> importJson(String payload) async {
    if (payload.length > 256 * 1024) {
      throw const FormatException('Payload too large (>256KB)');
    }
    final decoded = jsonDecode(payload);
    if (decoded is! List) throw const FormatException('Not an event list');
    if (decoded.length > 100) {
      throw const FormatException('Too many events (>100)');
    }
    var n = 0;
    for (final e in decoded) {
      try {
        await log(ThreatEvent.fromJson(
            Map<String, dynamic>.from(e as Map)));
        n++;
      } catch (_) {}
    }
    return n;
  }

  /// Helper to build an event from a finished scan.
  static ThreatEvent fromScan({
    required String source,
    required String category,
    required String risk,
    required int score,
    required double confidence,
    required List<SignalMatch> signals,
    required String fullText,
    bool demo = false,
  }) =>
      ThreatEvent(
        id: newId(),
        timestamp: DateTime.now().toIso8601String(),
        source: source,
        category: category,
        risk: risk,
        score: score,
        confidence: confidence,
        signals: signals.map((s) => s.id).toSet().toList(),
        evidenceCount: signals.length,
        preview: redactPreview(fullText),
        demo: demo,
      );
}
