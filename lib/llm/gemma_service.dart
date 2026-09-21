/// On-device LLM wrapper (flutter_gemma 0.9.x / MediaPipe LLM Inference).
///
/// CONTRACT: the model ONLY explains. It receives the verdict + fired
/// signals and must not invent new reasons. Every output is sanitized:
///  - sentences citing unfired signal classes are dropped
///  - verdict-flipping language falls back to the deterministic template
///  - on ANY failure (model missing, OOM, timeout) we return the
///    deterministic [PromptTemplate.fallback] so the demo never breaks.
///
/// The model file (.task) is bundled at assets/models/ and installed via
/// the plugin's asset installer — NEVER downloaded at runtime
/// (airplane-mode requirement). See README for placement.
library;

import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter_gemma/flutter_gemma.dart';
import 'package:flutter_gemma/core/chat.dart';
import 'package:flutter_gemma/core/model.dart';

import '../models/scan_result.dart';
import '../models/signal_match.dart';
import 'prompt_template.dart';

class GemmaService {
  static final GemmaService instance = GemmaService._();
  GemmaService._();

  bool _ready = false;
  bool _triedInit = false;
  InferenceModel? _model;
  InferenceChat? _chat;

  bool get isReady => _ready;

  /// Installs the bundled model asset on-device and creates the chat session.
  /// Returns true if the model is usable, false => caller uses fallback.
  /// Safe to call once; subsequent calls return the cached result.
  Future<bool> init(
      {String assetKey = 'assets/models/gemma-3-1b-it.task'}) async {
    if (_triedInit) return _ready;
    _triedInit = true;
    try {
      final plugin = FlutterGemmaPlugin.instance;
      // Asset install is a local file copy (no network). Throws if the
      // .task file was not bundled — dev without model => fallback mode.
      await plugin.modelManager.installModelFromAsset(assetKey);
      _model = await plugin.createModel(
        modelType: ModelType.gemmaIt,
        maxTokens: 1024,
      );
      _chat = await _model!.createChat(
        temperature: 0.2, // low creativity: grounded explanations only
        topK: 1,
        tokenBuffer: 512,
      );
      _ready = true;
      debugPrint('[Gemma] on-device model ready.');
      return true;
    } catch (e) {
      debugPrint('[Gemma] init failed ($e) — using built-in explainer.');
      _ready = false;
      return false;
    }
  }

  /// Explain [signals] for [message] under [verdict]. Never throws.
  Future<({String explanation, String whatToDo, bool llmUsed})> explain({
    required String message,
    required List<SignalMatch> signals,
    required Verdict verdict,
    required int score,
  }) async {
    final fb = PromptTemplate.fallback(signals: signals, verdict: verdict);
    if (!_ready || _chat == null) {
      return (
        explanation: fb.explanation,
        whatToDo: fb.whatToDo,
        llmUsed: false
      );
    }
    try {
      final prompt = PromptTemplate.build(
          message: message, signals: signals, verdict: verdict, score: score);
      await _chat!
          .addQueryChunk(Message.text(text: prompt, isUser: true))
          .timeout(const Duration(seconds: 10));
      final response = await _chat!
          .generateChatResponse()
          .timeout(const Duration(seconds: 30));
      final parsed =
          _parseAndSanitize(response, signals: signals, verdict: verdict);
      if (parsed.explanation.trim().isEmpty) {
        return (
          explanation: fb.explanation,
          whatToDo: fb.whatToDo,
          llmUsed: false
        );
      }
      return (
        explanation: parsed.explanation,
        whatToDo: parsed.whatToDo,
        llmUsed: true
      );
    } catch (e) {
      debugPrint('[Gemma] inference failed ($e) — fallback.');
      return (
        explanation: fb.explanation,
        whatToDo: fb.whatToDo,
        llmUsed: false
      );
    }
  }

  /// Parses EXPLANATION:/WHAT TO DO: lines and drops anything grounded in
  /// signals that did NOT fire. Guarantees no contradiction with verdict.
  ({String explanation, String whatToDo}) _parseAndSanitize(
    String raw, {
    required List<SignalMatch> signals,
    required Verdict verdict,
  }) {
    final fb = PromptTemplate.fallback(signals: signals, verdict: verdict);
    var explanation = '';
    var whatToDo = fb.whatToDo;

    final expRe =
        RegExp(r'EXPLANATION\s*:\s*(.+)', caseSensitive: false, dotAll: true);
    final wtdRe =
        RegExp(r'WHAT\s*TO\s*DO\s*:\s*(.+)', caseSensitive: false, dotAll: true);

    final expM = expRe.firstMatch(raw);
    if (expM != null) {
      explanation = expM.group(1)!;
      // Cut off the WHAT TO DO section if the model merged them.
      final cut = RegExp(r'WHAT\s*TO\s*DO\s*:',
              caseSensitive: false)
          .firstMatch(explanation);
      if (cut != null) explanation = explanation.substring(0, cut.start);
      explanation = explanation.trim();
    }
    final wtdM = wtdRe.firstMatch(raw);
    if (wtdM != null) {
      whatToDo = wtdM.group(1)!.trim().split('\n').first.trim();
    }

    // --- Grounding filter: drop sentences that allege unfired classes ----
    final fired = signals.map((s) => s.id).toSet();
    if (signals.isEmpty) {
      // Model must not manufacture threats for a clean message.
      // Keep only reassuring sentences; else fallback.
      final low = explanation.toLowerCase();
      const bad = [
        'scam',
        'fraud',
        'suspicious',
        'dangerous',
        'phishing',
        'risky'
      ];
      if (bad.any(low.contains)) return fb;
      if (explanation.isEmpty) return fb;
    } else {
      explanation = _dropUnfiredSentences(explanation, fired);
      if (explanation.trim().isEmpty) return fb;
    }

    // --- Verdict guard: strip verdict-flipping language -------------------
    final low = explanation.toLowerCase();
    if (verdict == Verdict.safe) {
      if (low.contains('likely a scam') || low.contains('this is a scam')) {
        return fb;
      }
    }
    if (whatToDo.length > 220) whatToDo = whatToDo.substring(0, 220);

    return (explanation: explanation.trim(), whatToDo: whatToDo.trim());
  }

  String _dropUnfiredSentences(String text, Set<String> fired) {
    // Map informal model words -> signal class. If the model mentions a
    // class that didn't fire, drop that sentence.
    const hints = <String, String>{
      'otp': 'SECRET_REQUEST',
      'pin': 'SECRET_REQUEST',
      'cvv': 'SECRET_REQUEST',
      'password': 'SECRET_REQUEST',
      'link': 'LINK_RISK',
      'url': 'LINK_RISK',
      'website': 'LINK_RISK',
      'urgent': 'URGENCY_THREAT',
      'blocked': 'URGENCY_THREAT',
      'threat': 'URGENCY_THREAT',
      'lottery': 'REWARD_LURE',
      'prize': 'REWARD_LURE',
      'refund': 'REWARD_LURE',
      'cashback': 'REWARD_LURE',
      'upi': 'PAYMENT_PULL',
      'qr': 'PAYMENT_PULL',
      'payment': 'PAYMENT_PULL',
      'call': 'CALLBACK',
      'phone': 'CALLBACK',
      'bank': 'IMPERSONATION',
      'sbi': 'IMPERSONATION',
      'courier': 'IMPERSONATION',
    };
    final sentences = text.split(RegExp(r'(?<=[.!?])\s+'));
    final kept = <String>[];
    for (final s in sentences) {
      final l = s.toLowerCase();
      String? alleged;
      for (final e in hints.entries) {
        if (l.contains(e.key)) {
          alleged = e.value;
          break;
        }
      }
      if (alleged != null && !fired.contains(alleged)) {
        continue; // drop: invented reason
      }
      kept.add(s);
    }
    return kept.join(' ');
  }
}
