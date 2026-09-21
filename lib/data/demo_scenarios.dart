/// Hackathon demo content: 6 scenarios + Scam Radar scripts + attack chain.
/// Every expected verdict is covered by tests — change text only with
/// `flutter test` green.
library;

import '../analysis/stages.dart';

enum ScenarioKind { single, radar, timeline }

class DemoScenario {
  final String id;
  final String title;
  final String subtitle;
  final ScenarioKind kind;
  final String expected;
  final String? text; // for single
  const DemoScenario({
    required this.id,
    required this.title,
    required this.subtitle,
    required this.kind,
    required this.expected,
    this.text,
  });
}

const demoScenarios = <DemoScenario>[
  DemoScenario(
    id: 'kyc',
    title: 'Scenario 1 · Fake KYC',
    subtitle: 'Lookalike bank link + OTP demand → HIGH',
    kind: ScenarioKind.single,
    expected: 'DANGEROUS',
    text: 'Dear Customer, your SBI Account KYC is expired and will be '
        'BLOCKED within 24 hours. Verify immediately at '
        'http://sbi-verify.xyz/kyc-update and share your OTP and ATM PIN '
        'to avoid suspension. Call 1800123456 for help.',
  ),
  DemoScenario(
    id: 'otp',
    title: 'Scenario 2 · Bank OTP scam',
    subtitle: 'Fake purchase alert + OTP block → HIGH',
    kind: ScenarioKind.single,
    expected: 'DANGEROUS',
    text: 'SBI ALERT: Rs.48,999 purchase attempt on your card. If this was '
        'not you, share the OTP sent to your mobile to block it immediately. '
        'Verify at http://sbisecure-alert.in/block or call 18002667777.',
  ),
  DemoScenario(
    id: 'courier',
    title: 'Scenario 3 · Fake courier fee',
    subtitle: 'Vague link + callback → MEDIUM',
    kind: ScenarioKind.single,
    expected: 'SUSPICIOUS',
    text: 'Hi, your courier package is waiting. Update your delivery address '
        'at https://delivery-update.com/track?id=12345 or call 9876543210 '
        'to confirm delivery.',
  ),
  DemoScenario(
    id: 'job',
    title: 'Scenario 4 · Part-time task job',
    subtitle: 'Telegram tasks + registration fee → HIGH',
    kind: ScenarioKind.single,
    expected: 'DANGEROUS',
    text: 'PART-TIME JOB from home! Earn Rs.5,000 per day liking videos. '
        'Daily tasks on Telegram, commission per task. Join '
        'http://bit.ly/task-earn9 and pay Rs.200 registration to '
        'taskpay@okhdfcbank to start today.',
  ),
  DemoScenario(
    id: 'arrest',
    title: 'Scenario 5 · Digital arrest call',
    subtitle: 'Simulated voice extortion → HIGH (Radar)',
    kind: ScenarioKind.radar,
    expected: 'DANGEROUS',
  ),
  DemoScenario(
    id: 'legit',
    title: 'Scenario 6 · Genuine alert',
    subtitle: 'Real-style bank SMS → LOW (the trust moment)',
    kind: ScenarioKind.single,
    expected: 'SAFE',
    text: 'Dear customer, Rs.12,450 credited to your SBI A/c XX1234 on '
        '20-Sep. Avl bal Rs.54,210. -SBI',
  ),
  DemoScenario(
    id: 'kyc-chain',
    title: 'Bonus · KYC attack chain',
    subtitle: 'Bait → link → harvest → OTP → fee (Timeline)',
    kind: ScenarioKind.timeline,
    expected: 'DANGEROUS',
  ),
];

class RadarLine {
  final String speaker; // 'Scammer' | 'You'
  final String text;
  const RadarLine(this.speaker, this.text);
}

/// Simulated incoming-call transcript. Clearly labeled SIMULATED in the UI —
/// no microphone recording, no STT; the text feed stands in for a live call.
const radarArrestScript = <RadarLine>[
  RadarLine('Scammer',
      'Hello, this is CBI officer Sharma. A parcel in your name was caught with narcotics.'),
  RadarLine('Scammer',
      'You are under DIGITAL ARREST. Do not disconnect this video call.'),
  RadarLine('Scammer',
      'Join the video call with the police for verification immediately.'),
  RadarLine('Scammer',
      'Share your Aadhaar and bank details to prove your innocence.'),
  RadarLine('You', 'But… how do I know this is real?'),
  RadarLine('Scammer',
      'Install this support app and share your screen so I can verify you.'),
  RadarLine('Scammer',
      'Transfer Rs.50,000 as a security deposit and tell me the OTP you just received. Hurry.'),
];

/// KYC multi-stage attack chain for the Timeline view.
const kycChainStages = <StageInput>[
  StageInput('1 · KYC bait',
      'SBI: Your KYC expires today. Update within 24 hours or your account will be BLOCKED.'),
  StageInput('2 · Phishing link',
      'Continue verification here: http://sbi-verify.xyz/kyc-update'),
  StageInput('3 · Credential harvest',
      'Enter PAN, account number and ATM PIN to verify identity.'),
  StageInput('4 · OTP theft',
      'An OTP has been sent to your mobile. Share it immediately to complete KYC.'),
  StageInput('5 · Payment fraud',
      'Pay Rs.99 verification fee at http://bit.ly/kyc-fee99 to taskpay@okhdfcbank or your KYC will be blocked.'),
];
