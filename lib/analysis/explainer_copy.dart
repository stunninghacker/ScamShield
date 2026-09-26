/// Plain-language copy for the "Why this verdict?" screen.
///
/// Every default-view string is traceable to a fired signal and avoids
/// jargon (checked by test). Technical detail (ids, offsets, weights,
/// strengths) lives only in the expandable judge section of the screen.
/// Pure Dart, deterministic, offline.
library;

import '../models/verdict.dart';
import 'attack_chain.dart';

/// Everyday title per signal class — no jargon.
const plainSignalTitle = <String, String>{
  'IMPERSONATION': 'Pretending to be someone you trust',
  'URGENCY_THREAT': 'Rushing you so you act without thinking',
  'DIGITAL_ARREST': 'Pretending to be police to scare you',
  'REWARD_LURE': 'A prize or refund to get you excited',
  'JOB_LURE': 'A job offer that sounds too easy',
  'LINK_RISK': 'A link that hides where it really goes',
  'SECRET_REQUEST': 'Asking for a code only you should know',
  'CALLBACK': 'A phone number controlled by strangers',
  'PAYMENT_PULL': 'Asking you to send money',
  'REMOTE_ACCESS': 'Wants a way into your phone',
};

/// Everyday "why this is dangerous" per signal class.
const plainSignalWhy = <String, String>{
  'IMPERSONATION':
      'Scammers borrow the name of a bank, the police, or a delivery '
      'company so you lower your guard. The real company did not send this.',
  'URGENCY_THREAT':
      'Threats and countdowns ("blocked in 10 minutes") are there to stop '
      'you from checking. Real banks and offices give you time.',
  'DIGITAL_ARREST':
      'There is no such thing as arrest over a video call. Real police '
      'never ask for money or secrecy on a call.',
  'REWARD_LURE':
      'Big prizes and easy refunds are bait. The "small fee" or details '
      'they ask for next are the real target.',
  'JOB_LURE':
      'Easy online jobs with daily pay are used to collect your bank '
      'details or make you move stolen money.',
  'LINK_RISK':
      'The link does not go where it claims. One tap can open a fake '
      'login page that steals what you type.',
  'SECRET_REQUEST':
      'Your OTP, PIN and passwords prove it is you. Anyone who gets them '
      'can take over your account. Real staff never ask for them.',
  'CALLBACK':
      'The number belongs to the scammers, not the company. Calling it '
      'connects you to someone trained to pressure you.',
  'PAYMENT_PULL':
      'Money sent this way is very hard to get back. Scammers invent '
      'fees, fines and verification charges to rush a payment.',
  'REMOTE_ACCESS':
      'Screen-sharing and support apps hand over your phone: messages, '
      'OTPs and bank apps included. Never install them for a stranger.',
};

/// One extra family-specific tip, plain words.
const familyAdvice = <ScamFamily, String>{
  ScamFamily.phishing:
      'Type the address yourself in your browser instead of tapping the link.',
  ScamFamily.bankingFraud:
      'Check your balance only in your bank\'s own app, then ignore this message.',
  ScamFamily.digitalArrest:
      'Hang up. Real police never arrest people over video calls.',
  ScamFamily.jobScam:
      'Never pay to join a job, and never share your bank login for one.',
  ScamFamily.remoteAccess:
      'Do not install the app, and uninstall it if you already did.',
  ScamFamily.deliveryScam:
      'Track parcels only in the courier\'s own app or website.',
  ScamFamily.investmentScam:
      'Guaranteed high profits are always a lie. Check only official investment apps.',
  ScamFamily.accountTakeover:
      'Change your password now using the company\'s own app or site.',
  ScamFamily.none:
      'Nothing risky was found, but stay alert if they write again.',
};

/// Recommended actions per verdict, plain words, most urgent first.
List<String> recommendedActions(Verdict verdict) {
  switch (verdict) {
    case Verdict.dangerous:
      return const [
        'Stop — do not reply, pay, tap, or call back.',
        'Check through the official app or a number you already trust.',
        'Warn a family member, then report (bank / 1930 helpline).',
      ];
    case Verdict.suspicious:
      return const [
        'Pause — do nothing in a hurry.',
        'Verify through the official app or a trusted number.',
        'Delete it if the sender cannot prove who they are.',
      ];
    case Verdict.safe:
      return const [
        'Nothing to do — this looks fine.',
        'Still never share OTPs or passwords with anyone.',
        'If they contact you again with threats or links, scan it here.',
      ];
  }
}

/// Evidence strength in words (numbers shown alongside, never alone).
String strengthWord(double strength) {
  if (strength >= 0.8) return 'Strong evidence';
  if (strength >= 0.65) return 'Moderate evidence';
  return 'Early sign';
}
