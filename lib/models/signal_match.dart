/// A single fired signal: WHAT matched, WHERE it matched, and how severe it is.
///
/// `start`/`end` are UTF-16 code-unit offsets into the original source text
/// (i.e. valid arguments to `String.substring(start, end)`), so the UI can
/// highlight the EXACT substring the rule engine flagged. No guessing.
class SignalMatch {
  final String id; // e.g. 'LINK_RISK', 'SECRET_REQUEST'
  final String label; // human-readable, e.g. 'Suspicious link'
  final int weight; // severity weight contributed to the total score
  final String matchedText; // exact substring that fired
  final int start; // inclusive offset in source text
  final int end; // exclusive offset in source text
  final String detail; // short machine note, e.g. 'shortener: bit.ly'

  const SignalMatch({
    required this.id,
    required this.label,
    required this.weight,
    required this.matchedText,
    required this.start,
    required this.end,
    this.detail = '',
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'label': label,
        'weight': weight,
        'matchedText': matchedText,
        'start': start,
        'end': end,
        'detail': detail,
      };

  factory SignalMatch.fromJson(Map<String, dynamic> j) => SignalMatch(
        id: j['id'] as String,
        label: j['label'] as String,
        weight: (j['weight'] as num).toInt(),
        matchedText: j['matchedText'] as String,
        start: (j['start'] as num).toInt(),
        end: (j['end'] as num).toInt(),
        detail: (j['detail'] ?? '') as String,
      );
}
