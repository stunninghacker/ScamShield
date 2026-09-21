/// One shared scan entry-point for paste / demo / photo / URL-as-text.
/// Shows progress, runs the pipeline (and logs the event), opens Result.
library;

import 'package:flutter/material.dart';
import '../analysis/scan_pipeline.dart';
import 'result_screen.dart';

Future<void> runTextScan(
  BuildContext context,
  String text, {
  String source = 'text',
  bool demo = false,
  bool staged = false,
}) async {
  final trimmed = text.trim();
  if (trimmed.isEmpty) {
    ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Paste a message first.')));
    return;
  }
  showDialog(
    context: context,
    barrierDismissible: false,
    builder: (_) => const Center(child: CircularProgressIndicator()),
  );
  PipelineResult result;
  try {
    result = await ScanPipeline.instance
        .analyze(trimmed, source: source, demo: demo);
  } finally {
    if (context.mounted) Navigator.of(context).pop();
  }
  if (!context.mounted) return;
  await Navigator.of(context).push(
    MaterialPageRoute(
        builder: (_) => ResultScreen(result: result, staged: staged)),
  );
}
