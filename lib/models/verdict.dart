/// Risk verdict owned SOLELY by the rule engine. The LLM never changes this.
library;

enum Verdict { safe, suspicious, dangerous }

extension VerdictX on Verdict {
  String get label {
    switch (this) {
      case Verdict.safe:
        return 'Looks genuine';
      case Verdict.suspicious:
        return 'Looks suspicious';
      case Verdict.dangerous:
        return 'Likely a scam';
    }
  }

  String get riskWord {
    switch (this) {
      case Verdict.safe:
        return 'LOW';
      case Verdict.suspicious:
        return 'MEDIUM';
      case Verdict.dangerous:
        return 'HIGH';
    }
  }

  String get nameUpper => name.toUpperCase();
}
