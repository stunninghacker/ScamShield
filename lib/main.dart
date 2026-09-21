import 'package:flutter/material.dart';
import 'settings/app_settings.dart';
import 'ui/shell.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await AppSettings.instance.load();
  runApp(const ScamShieldApp());
}

class ScamShieldApp extends StatelessWidget {
  const ScamShieldApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: AppSettings.instance,
      builder: (_, __) => MaterialApp(
        title: 'ScamShield',
        debugShowCheckedModeBanner: false,
        themeMode: AppSettings.instance.themeMode,
        theme: ThemeData(
          colorScheme: ColorScheme.fromSeed(
              seedColor: const Color(0xFF1B5E20)),
          useMaterial3: true,
        ),
        darkTheme: ThemeData(
          colorScheme: ColorScheme.fromSeed(
              seedColor: const Color(0xFF1B5E20),
              brightness: Brightness.dark),
          useMaterial3: true,
        ),
        home: const Shell(),
      ),
    );
  }
}
