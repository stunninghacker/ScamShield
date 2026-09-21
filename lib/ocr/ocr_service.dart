/// Offline OCR via ML Kit Text Recognition (Latin script).
/// Fully on-device after first model provisioning — no network at runtime.
/// If OCR fails, callers fall back to manual paste (demo reliability).
library;

import 'dart:io';
import 'package:google_mlkit_text_recognition/google_mlkit_text_recognition.dart';

class OcrResult {
  final String text;
  const OcrResult(this.text);
}

class OcrService {
  OcrService._();
  static final OcrService instance = OcrService._();

  TextRecognizer? _recognizer;

  TextRecognizer get _rec {
    _recognizer ??= TextRecognizer(script: TextRecognitionScript.latin);
    return _recognizer!;
  }

  /// Recognizes text from an image file shared INTO the app.
  /// Throws on failure — callers catch and show paste fallback.
  Future<OcrResult> recognizeFile(File image) async {
    final input = InputImage.fromFile(image);
    final result = await _rec.processImage(input);
    return OcrResult(result.text.trim());
  }

  Future<void> dispose() async {
    await _recognizer?.close();
    _recognizer = null;
  }
}
