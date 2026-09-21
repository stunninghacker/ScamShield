/// Receives shared content from other apps (SMS/WhatsApp -> Share).
/// Handles: shared TEXT (forwarded SMS, via SharedMediaType.text) and
/// shared IMAGE files (screenshots, via SharedMediaType.image -> OCR).
/// Purely local routing — no network.
library;

import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:receive_sharing_intent/receive_sharing_intent.dart';
import '../ocr/ocr_service.dart';

/// A piece of incoming shared content, already converted to text when possible.
class IncomingShare {
  final String text; // OCR'd or directly-shared text
  final bool fromImage; // true if it came via OCR
  const IncomingShare(this.text, {this.fromImage = false});
}

class ShareHandler {
  StreamSubscription? _mediaSub;

  /// Handles one batch of shared files (text passes through, images go to
  /// offline OCR). Shared text arrives as SharedMediaFile with type `text`
  /// and the message in [SharedMediaFile.path].
  Future<void> _handleBatch(
      List<SharedMediaFile> files, void Function(IncomingShare) onShare) async {
    for (final f in files) {
      if (f.type == SharedMediaType.image) {
        try {
          final ocr = await OcrService.instance.recognizeFile(File(f.path));
          if (ocr.text.isNotEmpty) {
            onShare(IncomingShare(ocr.text, fromImage: true));
          }
        } catch (e) {
          debugPrint('[Share] OCR failed: $e');
        }
      } else if (f.type == SharedMediaType.text ||
          f.type == SharedMediaType.url) {
        final text = f.type == SharedMediaType.text
            ? f.path
            : (f.message?.isNotEmpty == true ? f.message! : f.path);
        if (text.trim().isNotEmpty) onShare(IncomingShare(text));
      }
    }
  }

  /// Starts listening. [onShare] is called with extracted text.
  void listen(void Function(IncomingShare share) onShare) {
    _mediaSub = ReceiveSharingIntent.instance.getMediaStream().listen(
      (List<SharedMediaFile> files) => _handleBatch(files, onShare),
      onError: (e) => debugPrint('[Share] media stream error: $e'),
    );
  }

  /// Cold-start intents (app launched via Share). Call once from Home init.
  Future<IncomingShare?> initialShare() async {
    try {
      final media = await ReceiveSharingIntent.instance.getInitialMedia();
      IncomingShare? found;
      await _handleBatch(media, (s) => found ??= s);
      // Consume so the same share isn't delivered twice.
      await ReceiveSharingIntent.instance.reset();
      return found;
    } catch (e) {
      debugPrint('[Share] initial intent error: $e');
      return null;
    }
  }

  void dispose() {
    _mediaSub?.cancel();
  }
}
