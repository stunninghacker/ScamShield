/// App-wide settings (theme, family mode, trusted contact).
/// Persisted locally, never leaves the phone.
library;

import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

class AppSettings extends ChangeNotifier {
  static final AppSettings instance = AppSettings._();
  AppSettings._();

  bool darkMode = false;
  bool familyMode = false;
  String trustedContact = '';

  bool _loaded = false;

  Future<void> load() async {
    if (_loaded) return;
    _loaded = true;
    try {
      final p = await SharedPreferences.getInstance();
      darkMode = p.getBool('scamshield_dark') ?? false;
      familyMode = p.getBool('scamshield_family') ?? false;
      trustedContact = p.getString('scamshield_contact') ?? '';
      notifyListeners();
    } catch (_) {}
  }

  ThemeMode get themeMode => darkMode ? ThemeMode.dark : ThemeMode.light;

  Future<void> setDark(bool v) async {
    darkMode = v;
    notifyListeners();
    try {
      (await SharedPreferences.getInstance())
          .setBool('scamshield_dark', v);
    } catch (_) {}
  }

  Future<void> setFamily(bool v) async {
    familyMode = v;
    notifyListeners();
    try {
      (await SharedPreferences.getInstance())
          .setBool('scamshield_family', v);
    } catch (_) {}
  }

  Future<void> setContact(String v) async {
    trustedContact = v.trim();
    notifyListeners();
    try {
      (await SharedPreferences.getInstance())
          .setString('scamshield_contact', trustedContact);
    } catch (_) {}
  }
}
