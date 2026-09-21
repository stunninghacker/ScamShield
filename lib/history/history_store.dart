/// Local-only scan history (shared_preferences). No cloud, no telemetry.
library;

import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/scan_result.dart';

class HistoryStore {
  static const _key = 'scamshield_history_v1';
  static const maxItems = 50;

  Future<List<ScanResult>> load() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_key) ?? const [];
    final out = <ScanResult>[];
    for (final s in raw) {
      try {
        out.add(ScanResult.fromJson(
            Map<String, dynamic>.from(jsonDecode(s) as Map)));
      } catch (_) {
        // skip corrupt entries
      }
    }
    return out;
  }

  Future<void> save(ScanResult r) async {
    final prefs = await SharedPreferences.getInstance();
    final current = prefs.getStringList(_key) ?? <String>[];
    current.insert(0, jsonEncode(r.toJson()));
    while (current.length > maxItems) {
      current.removeLast();
    }
    await prefs.setStringList(_key, current);
  }

  Future<void> clear() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_key);
  }
}
