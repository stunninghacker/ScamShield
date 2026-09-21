/// The 4 hard-coded demo samples. Chosen to land exact verdicts.
/// Do NOT edit text lightly — scores are tuned to these strings.
library;

class DemoSample {
  final String title;
  final String subtitle;
  final String text;
  final String expectedVerdict; // 'DANGEROUS' | 'SUSPICIOUS' | 'SAFE'
  const DemoSample({
    required this.title,
    required this.subtitle,
    required this.text,
    required this.expectedVerdict,
  });
}

const demoSamples = <DemoSample>[
  DemoSample(
    title: 'Demo 1 · Fake KYC + OTP',
    subtitle: 'Lookalike bank link → DANGEROUS',
    expectedVerdict: 'DANGEROUS',
    text: 'Dear Customer, your SBI Account KYC is expired and will be '
        'BLOCKED within 24 hours. Verify immediately at '
        'http://sbi-verify.xyz/kyc-update and share your OTP and ATM PIN '
        'to avoid suspension. Call 1800123456 for help.',
  ),
  DemoSample(
    title: 'Demo 2 · Lottery fee lure',
    subtitle: 'Prize + UPI fee → DANGEROUS',
    expectedVerdict: 'DANGEROUS',
    text: 'Congratulations! You won KBC lottery Rs.25,00,000! You are a '
        'lucky winner. Claim your prize now — pay Rs.499 processing fee to '
        'winner-claim@okhdfcbank to receive your refund. Visit '
        'http://bit.ly/kbc-win2024 Hurry, offer ends today!',
  ),
  DemoSample(
    title: 'Demo 3 · Courier borderline',
    subtitle: 'Vague link + callback → SUSPICIOUS',
    expectedVerdict: 'SUSPICIOUS',
    text: 'Hi, your courier package is waiting. Update your delivery address '
        'at https://delivery-update.com/track?id=12345 or call 9876543210 '
        'to confirm delivery.',
  ),
  DemoSample(
    title: 'Demo 4 · Genuine bank alert',
    subtitle: 'No link, no secret → SAFE',
    expectedVerdict: 'SAFE',
    text: 'Dear customer, Rs.12,450 credited to your SBI A/c XX1234 on '
        '20-Sep. Avl bal Rs.54,210. -SBI',
  ),
];
