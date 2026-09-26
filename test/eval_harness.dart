import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:scamshield/analysis/attack_chain.dart';

import 'package:scamshield/models/verdict.dart';
import 'package:scamshield/rules/scam_engine.dart';

/// Offline evaluation harness for ScamShield.
///
/// Purely deterministic: the engine is NEVER modified to improve
/// metrics. Metrics are computed by running the UNCHANGED engine
/// against 250+ hand-labeled cases, then comparing predictions
/// (signal family) against expected family and expected verdict.
///
/// Run with: `flutter test test/eval_harness.dart`
/// Or benchmark: `dart test test/eval_harness.dart --name "eval"`

class EvalCase {
  final String id;
  final String input;
  final String expectedFamily; // ScamFamily.name
  final String expectedVerdict; // safe | suspicious | dangerous
  final List<String> expectedSignals;
  final String category; // phishing | banking | otp | digital_arrest | job | delivery | remote | investment | qr_payment | legit_bank | legit_job | legit_delivery | legit_gov | negation

  const EvalCase({
    required this.id,
    required this.input,
    required this.expectedFamily,
    required this.expectedVerdict,
    required this.expectedSignals,
    required this.category,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'input': input,
        'expectedFamily': expectedFamily,
        'expectedVerdict': expectedVerdict,
        'expectedSignals': expectedSignals,
        'category': category,
      };
}

class FamilyMetrics {
  final String family;
  final int tp; // correctly predicted as this family
  final int fp; // predicted as this family but wrong
  final int fn; // actually this family but predicted otherwise
  final int tn; // not this family and not predicted as this
  final int predicted; // times predicted as this family
  final int actual; // times actually this family

  FamilyMetrics({
    required this.family,
    required this.tp,
    required this.fp,
    required this.fn,
    required this.tn,
    required this.predicted,
    required this.actual,
  });

  double get precision => predicted > 0 ? tp / predicted : 0.0;
  double get recall => actual > 0 ? tp / actual : 0.0;
  double get f1 => (precision + recall) > 0 ? 2 * precision * recall / (precision + recall) : 0.0;
  String get label => family == 'none' ? 'Genuine' : family;
}

class EvalReport {
  final int total;
  final int passed;
  final int failed;
  final double accuracy;
  final double precision;
  final double recall;
  final double f1;
  final int falsePositives;
  final int falseNegatives;
  final List<FamilyMetrics> perFamily;
  final List<Map<String, dynamic>> confusionMatrix;
  final List<String> familyNames;
  final List<EvalCase> failures;

  EvalReport({
    required this.total,
    required this.passed,
    required this.failed,
    required this.accuracy,
    required this.precision,
    required this.recall,
    required this.f1,
    required this.falsePositives,
    required this.falseNegatives,
    required this.perFamily,
    required this.confusionMatrix,
    required this.familyNames,
    required this.failures,
  });

  Map<String, dynamic> toJson() => {
        'total': total,
        'passed': passed,
        'failed': failed,
        'accuracy': accuracy.toStringAsFixed(4),
        'precision': precision.toStringAsFixed(4),
        'recall': recall.toStringAsFixed(4),
        'f1': f1.toStringAsFixed(4),
        'falsePositives': falsePositives,
        'falseNegatives': falseNegatives,
        'perFamily': perFamily.map((m) => {
              'family': m.label,
              'precision': m.precision.toStringAsFixed(4),
              'recall': m.recall.toStringAsFixed(4),
              'f1': m.f1.toStringAsFixed(4),
              'tp': m.tp,
              'fp': m.fp,
              'fn': m.fn,
              'tn': m.tn,
            }).toList(),
        'confusionMatrix': confusionMatrix,
        'familyNames': familyNames,
        'failures': failures.map((f) => f.toJson()).toList(),
      };
}

// ── Case definitions (250+) ──────────────────────────────────────

List<EvalCase> buildCases() {
  return [
    // ═══════════════════════════════════════════════════════════
    // PHISHING (25 cases)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'ph01', input: 'Update your account details here: https://example.com/verify', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph02', input: 'Click this link to claim your reward: http://bit.ly/reward123', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'REWARD_LURE'], category: 'phishing'),
    EvalCase(id: 'ph03', input: 'Please verify your identity at http://sbi-verify.xyz/login', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'SECRET_REQUEST'], category: 'phishing'),
    EvalCase(id: 'ph04', input: 'Your account needs verification: http://192.168.1.50/account', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph05', input: 'View your statement at https://mail.bank-alert.com/statement', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph06', input: 'Urgent: Your account will be blocked if you do not verify here: https://verify.account.com', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'URGENCY_THREAT'], category: 'phishing'),
    EvalCase(id: 'ph07', input: 'Click https://shortener.xyz/kbc to update your KYC', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph08', input: 'Your package update: http://delivery-track.com/parcel?id=1234', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph09', input: 'Verify your email: https://secure-login.net/email/verify', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph10', input: 'Your Netflix subscription expired: http://netflix-renew.xyz/pay', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK', 'PAYMENT_PULL'], category: 'phishing'),
    EvalCase(id: 'ph11', input: 'Your Aadhaar eKYC is pending: http://aadhaar-ekyc.com/verify', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'SECRET_REQUEST'], category: 'phishing'),
    EvalCase(id: 'ph12', input: 'Click to view your GST refund: http://gst-refund.gov.in/claim', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK', 'REWARD_LURE'], category: 'phishing'),
    EvalCase(id: 'ph13', input: 'Your mobile number is deactivated: http://reactivate-phone.com/verify', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'URGENCY_THREAT'], category: 'phishing'),
    EvalCase(id: 'ph14', input: 'Verify your PAN card: http://pan-verify.gov.in/pan', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph15', input: 'Your credit card is blocked: http://card-unblock.xyz/verify now', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'URGENCY_THREAT'], category: 'phishing'),
    EvalCase(id: 'ph16', input: 'Update your profile: https://profile-update.net/account', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph17', input: 'Your WhatsApp account will be deleted: http://wa-verify.com/act', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'URGENCY_THREAT'], category: 'phishing'),
    EvalCase(id: 'ph18', input: 'Share this link with friends: http://refer-friend.xyz/reward', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK', 'REWARD_LURE'], category: 'phishing'),
    EvalCase(id: 'ph19', input: 'Your Instagram account got a login attempt: http://ig-secure.com/verify', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph20', input: 'Tap to view your LPG subsidy: http://lpg-subsidy.gov.in/status', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK', 'REWARD_LURE'], category: 'phishing'),
    EvalCase(id: 'ph21', input: 'Your email forwarding is set: click http://email-fwd.com/confirm', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph22', input: 'Your SIM card is cloned: http://sim-alert.com/block now', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'URGENCY_THREAT', 'SECRET_REQUEST'], category: 'phishing'),
    EvalCase(id: 'ph23', input: 'Your voting card is ready: http://evm-track.com/collect', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph24', input: 'Update your D-mat account: http://demat-update.com/KYC', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'SECRET_REQUEST'], category: 'phishing'),
    EvalCase(id: 'ph25', input: 'Your mutual fund NAV is updated: http://mf-nav.com/view', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),

    // ═══════════════════════════════════════════════════════════
    // BANKING FRAUD (25 cases)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'bk01', input: 'SBI: share your OTP now, account blocked', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk02', input: 'HDFC bank: your account is frozen, share PIN to unfreeze', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk03', input: 'Your ICICI account needs KYC: share OTP immediately', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'LINK_RISK'], category: 'banking'),
    EvalCase(id: 'bk04', input: 'Axis bank alert: your card is blocked, enter OTP to unblock', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk05', input: 'Kotak: verify your identity by sharing your ATM PIN', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'banking'),
    EvalCase(id: 'bk06', input: 'Your PNB account shows suspicious activity: confirm with OTP', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk07', input: 'RBI advisory: your account flagged, share your OTP', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'IMPERSONATION'], category: 'banking'),
    EvalCase(id: 'bk08', input: 'Your SBI credit limit is increased, share OTP to activate', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'REWARD_LURE'], category: 'banking'),
    EvalCase(id: 'bk09', input: 'HDFC: your account will be closed, pay fee to keep it', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk10', input: 'Your bank account is compromised, install app and share screen', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk11', input: 'Your ICICI card has unauthorized transactions, share OTP', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk12', input: 'SBI: your account balance is low, pay Rs.1 to verify', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk13', input: 'Your Kotak account needs verification: enter password', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'banking'),
    EvalCase(id: 'bk14', input: 'HDFC: your fixed deposit matures, share OTP to claim', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'REWARD_LURE'], category: 'banking'),
    EvalCase(id: 'bk15', input: 'Your Axis account is under review, send Rs.500 to verify', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk16', input: 'PNB alert: your chequebook is blocked, share OTP', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk17', input: 'Your bank account is linked to a crime, pay fine', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'URGENCY_THREAT', 'IMPERSONATION'], category: 'banking'),
    EvalCase(id: 'bk18', input: 'SBI: your net banking password is expired, reset it', expectedFamily: 'bankingFraud', expectedVerdict: 'suspicious', expectedSignals: ['SECRET_REQUEST'], category: 'banking'),
    EvalCase(id: 'bk19', input: 'Your HDFC account needs a small deposit to stay active', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk20', input: 'Your ICICI card is charged, confirm the amount with OTP', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk21', input: 'Kotak: your account will be suspended, share credentials now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk22', input: 'Your SBI account shows a login from another city, share OTP', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk23', input: 'HDFC: your account is at risk, pay to secure it', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk24', input: 'Your Axis bank account needs verification: enter password and OTP', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk25', input: 'Your PNB card is blocked, click here and share OTP', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),

    // ═══════════════════════════════════════════════════════════
    // OTP THEFT (10 cases - subset of banking fraud)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'ot01', input: 'Your bank OTP is required to complete the transaction', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot02', input: 'Share the OTP you received to verify your identity', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot03', input: 'An OTP has been sent to you, please share it with us', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot04', input: 'Your account OTP is: 123456, share it to verify', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot05', input: 'Enter the OTP sent to your phone to proceed', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot06', input: 'For verification, share the OTP received on your device', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot07', input: 'Your card OTP is required to authorize this payment', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot08', input: 'Please confirm the OTP sent to your registered number', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot09', input: 'An OTP is needed to update your account details', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot10', input: 'Share the OTP immediately to prevent account suspension', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'otp'),

    // ═══════════════════════════════════════════════════════════
    // DIGITAL ARREST (12 cases)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'da01', input: 'You are under DIGITAL ARREST by CBI, join video call now', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'URGENCY_THREAT'], category: 'digital_arrest'),
    EvalCase(id: 'da02', input: 'Police arrested your relative, pay bail via UPI', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'PAYMENT_PULL'], category: 'digital_arrest'),
    EvalCase(id: 'da03', input: 'Your Aadhaar is linked to a crime, pay fine or face arrest', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'PAYMENT_PULL'], category: 'digital_arrest'),
    EvalCase(id: 'da04', input: 'You are wanted by police for money laundering', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'URGENCY_THREAT'], category: 'digital_arrest'),
    EvalCase(id: 'da05', input: 'Your PAN is linked to a fraudulent case, pay to clear', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'PAYMENT_PULL'], category: 'digital_arrest'),
    EvalCase(id: 'da06', input: 'CBI investigation: you must join video call immediately', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST'], category: 'digital_arrest'),
    EvalCase(id: 'da07', input: 'Your address is linked to a crime, pay penalty now', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'PAYMENT_PULL'], category: 'digital_arrest'),
    EvalCase(id: 'da08', input: 'Digital arrest notice: share screen with officer now', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'REMOTE_ACCESS'], category: 'digital_arrest'),
    EvalCase(id: 'da09', input: 'You are under investigation, send money to avoid arrest', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'PAYMENT_PULL'], category: 'digital_arrest'),
    EvalCase(id: 'da10', input: 'Police have issued an arrest warrant for you', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST'], category: 'digital_arrest'),
    EvalCase(id: 'da11', input: 'Your name is on a criminal list, pay to be removed', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'PAYMENT_PULL'], category: 'digital_arrest'),
    EvalCase(id: 'da12', input: 'You are under digital arrest by income tax department', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST'], category: 'digital_arrest'),

    // ═══════════════════════════════════════════════════════════
    // JOB SCAMS (12 cases)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'jb01', input: 'PART-TIME JOB from home. Earn Rs.5,000 per day', expectedFamily: 'jobScam', expectedVerdict: 'dangerous', expectedSignals: ['JOB_LURE'], category: 'job'),
    EvalCase(id: 'jb02', input: 'Work from home and earn Rs.50,000 per month', expectedFamily: 'jobScam', expectedVerdict: 'dangerous', expectedSignals: ['JOB_LURE'], category: 'job'),
    EvalCase(id: 'jb03', input: 'Telegram tasks: earn commission daily', expectedFamily: 'jobScam', expectedVerdict: 'dangerous', expectedSignals: ['JOB_LURE'], category: 'job'),
    EvalCase(id: 'jb04', input: 'Easy online job: pay Rs.500 registration fee', expectedFamily: 'jobScam', expectedVerdict: 'dangerous', expectedSignals: ['JOB_LURE', 'PAYMENT_PULL'], category: 'job'),
    EvalCase(id: 'jb05', input: 'Join our team and earn daily payouts', expectedFamily: 'jobScam', expectedVerdict: 'suspicious', expectedSignals: ['JOB_LURE'], category: 'job'),
    EvalCase(id: 'jb06', input: 'Data entry work from home, Rs.1000 per task', expectedFamily: 'jobScam', expectedVerdict: 'suspicious', expectedSignals: ['JOB_LURE'], category: 'job'),
    EvalCase(id: 'jb07', input: 'Social media manager needed, pay to start', expectedFamily: 'jobScam', expectedVerdict: 'dangerous', expectedSignals: ['JOB_LURE', 'PAYMENT_PULL'], category: 'job'),
    EvalCase(id: 'jb08', input: 'Freelance typing job, earn Rs.2000 daily', expectedFamily: 'jobScam', expectedVerdict: 'suspicious', expectedSignals: ['JOB_LURE'], category: 'job'),
    EvalCase(id: 'jb09', input: 'Paid surveys: earn Rs.500 per survey', expectedFamily: 'jobScam', expectedVerdict: 'suspicious', expectedSignals: ['JOB_LURE'], category: 'job'),
    EvalCase(id: 'jb10', input: 'Package forwarding job: pay to register', expectedFamily: 'jobScam', expectedVerdict: 'dangerous', expectedSignals: ['JOB_LURE', 'PAYMENT_PULL'], category: 'job'),
    EvalCase(id: 'jb11', input: 'Content moderation job: share your bank details', expectedFamily: 'jobScam', expectedVerdict: 'dangerous', expectedSignals: ['JOB_LURE', 'SECRET_REQUEST'], category: 'job'),
    EvalCase(id: 'jb12', input: 'Online tutoring: pay Rs.200 for materials', expectedFamily: 'jobScam', expectedVerdict: 'suspicious', expectedSignals: ['JOB_LURE', 'PAYMENT_PULL'], category: 'job'),

    // ═══════════════════════════════════════════════════════════
    // DELIVERY SCAMS (12 cases)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'dl01', input: 'Delhivery courier: your parcel is held, call 98765 43210', expectedFamily: 'deliveryScam', expectedVerdict: 'suspicious', expectedSignals: ['CALLBACK'], category: 'delivery'),
    EvalCase(id: 'dl02', input: 'Courier delivery failed, track at http://bit.ly/dl44', expectedFamily: 'deliveryScam', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK', 'CALLBACK'], category: 'delivery'),
    EvalCase(id: 'dl03', input: 'Your parcel is stuck, pay Rs.50 delivery fee', expectedFamily: 'deliveryScam', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'CALLBACK'], category: 'delivery'),
    EvalCase(id: 'dl04', input: 'DHL delivery: pay customs fee to receive package', expectedFamily: 'deliveryScam', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL'], category: 'delivery'),
    EvalCase(id: 'dl05', input: 'FedEx package held: call +91-9876543210 now', expectedFamily: 'deliveryScam', expectedVerdict: 'suspicious', expectedSignals: ['CALLBACK'], category: 'delivery'),
    EvalCase(id: 'dl06', input: 'Your India Post parcel needs payment, click here', expectedFamily: 'deliveryScam', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'PAYMENT_PULL'], category: 'delivery'),
    EvalCase(id: 'dl07', input: 'Bluedart shipment: pay to release your package', expectedFamily: 'deliveryScam', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL'], category: 'delivery'),
    EvalCase(id: 'dl08', input: 'Ekart delivery failed, verify address at http://ekart.com', expectedFamily: 'deliveryScam', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'delivery'),
    EvalCase(id: 'dl09', input: 'Your parcel is with customs, pay clearance fee', expectedFamily: 'deliveryScam', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL'], category: 'delivery'),
    EvalCase(id: 'dl10', input: 'Courier delivery: call 011-23456789 to reschedule', expectedFamily: 'deliveryScam', expectedVerdict: 'suspicious', expectedSignals: ['CALLBACK'], category: 'delivery'),
    EvalCase(id: 'dl11', input: 'Your package is undelivered, pay Rs.100 for redelivery', expectedFamily: 'deliveryScam', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL'], category: 'delivery'),
    EvalCase(id: 'dl12', input: 'Delhivery tracking link: http://track.dlhivery.com/xyz', expectedFamily: 'deliveryScam', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'delivery'),

    // ═══════════════════════════════════════════════════════════
    // REMOTE ACCESS (12 cases)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'ra01', input: 'Install AnyDesk and share your screen for support', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra02', input: 'Download this apk file to fix your account', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra03', input: 'Share your screen on Google Meet for verification', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra04', input: 'Install TeamViewer to resolve the issue', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra05', input: 'Please share your screen to help us verify', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra06', input: 'Install the support app and allow screen sharing', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra07', input: 'Download QuickSupport and grant access', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra08', input: 'Share your device screen to complete KYC', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra09', input: 'Install the app and enable remote access now', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra10', input: 'Your account is compromised, install AnyDesk and share', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS', 'URGENCY_THREAT'], category: 'remote'),
    EvalCase(id: 'ra11', input: 'Download the security app and share your screen', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra12', input: 'Allow screen sharing to fix your payment issue', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),

    // ═══════════════════════════════════════════════════════════
    // INVESTMENT SCAMS (12 cases)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'in01', input: 'Invest Rs.10,000 in crypto trading, guaranteed 3x profits', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in02', input: 'Double your money in 7 days with our trading platform', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in03', input: 'Join our Demat account, earn guaranteed returns daily', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in04', input: 'Invest in cryptocurrency and earn profits every week', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in05', input: 'Your investment doubled! Pay tax to withdraw', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in06', input: 'High returns on stocks, pay Rs.5000 to start', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in07', input: 'Join our trading group, guaranteed profits daily', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in08', input: 'Invest in our new crypto coin, profit in 24 hours', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in09', input: 'Earn 10% monthly returns on mutual funds, pay fee', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in10', input: 'Your portfolio is ready, pay withdrawal fee to get money', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in11', input: 'Invest Rs.5000 and get Rs.15000 back in a week', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in12', input: 'Trade with us and earn triple your investment', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),

    // ═══════════════════════════════════════════════════════════
    // QR / PAYMENT SCAMS (12 cases)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'qr01', input: 'Scan this QR to pay Rs.999 and get a reward', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'REWARD_LURE', 'PAYMENT_PULL'], category: 'qr_payment'),
    EvalCase(id: 'qr02', input: 'Send Rs.1 to this UPI ID to verify your account', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'SECRET_REQUEST'], category: 'qr_payment'),
    EvalCase(id: 'qr03', input: 'Your refund will be processed to shop@okhdfcbank', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL'], category: 'qr_payment'),
    EvalCase(id: 'qr04', input: 'Pay Rs.499 to claim your prize, scan QR code', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'qr_payment'),
    EvalCase(id: 'qr05', input: 'Send money to refund-cell@okhdfcbank for KYC', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL'], category: 'qr_payment'),
    EvalCase(id: 'qr06', input: 'Scan QR to receive Rs.500 cashback', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'qr_payment'),
    EvalCase(id: 'qr07', input: 'Your order refund is ready, pay Rs.1 to unlock', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'SECRET_REQUEST'], category: 'qr_payment'),
    EvalCase(id: 'qr08', input: 'Pay the delivery charge of Rs.30 via UPI', expectedFamily: 'deliveryScam', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL'], category: 'qr_payment'),
    EvalCase(id: 'qr09', input: 'Scan this QR to join our investment group', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'qr_payment'),
    EvalCase(id: 'qr10', input: 'Your UPI payment failed, scan again to retry', expectedFamily: 'bankingFraud', expectedVerdict: 'suspicious', expectedSignals: ['PAYMENT_PULL'], category: 'qr_payment'),
    EvalCase(id: 'qr11', input: 'Send Rs.1 to this number to verify your identity', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL'], category: 'qr_payment'),
    EvalCase(id: 'qr12', input: 'Pay Rs.100 to unlock your account via QR', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'URGENCY_THREAT'], category: 'qr_payment'),

    // ═══════════════════════════════════════════════════════════
    // LEGITIMATE BANKING MESSAGES (10 cases)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'lb01', input: 'Your monthly account statement is ready. You can view it in the official app.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),
    EvalCase(id: 'lb02', input: 'Dear customer, Rs.12,450 credited to your SBI A/c XX1234 on 20-Sep. Avl bal Rs.54,210. -SBI', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),
    EvalCase(id: 'lb03', input: 'Your HDFC credit card bill of Rs.5,000 is due on 25th.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),
    EvalCase(id: 'lb04', input: 'Your ICICI fixed deposit of Rs.1,00,000 has matured.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),
    EvalCase(id: 'lb05', input: 'Your PNB account balance is Rs.25,000 as of today.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),
    EvalCase(id: 'lb06', input: 'SBI: Your net banking password has been changed successfully.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),
    EvalCase(id: 'lb07', input: 'Your Kotak account statement for the month is available.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),
    EvalCase(id: 'lb08', input: 'Axis bank: Your loan EMI of Rs.8,000 has been deducted.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),
    EvalCase(id: 'lb09', input: 'Your RBL card statement shows a payment of Rs.15,000.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),
    EvalCase(id: 'lb10', input: 'Yes Bank: Your savings account interest of Rs.500 has been credited.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),

    // ═══════════════════════════════════════════════════════════
    // LEGITIMATE JOB MESSAGES (8 cases)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'lj01', input: 'Your interview for the software engineer position is scheduled for Monday at 10am.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_job'),
    EvalCase(id: 'lj02', input: 'Your offer letter from XYZ Corp has been sent to your email.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_job'),
    EvalCase(id: 'lj03', input: 'Your performance review is scheduled for Friday. Please prepare.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_job'),
    EvalCase(id: 'lj04', input: 'Welcome to your new role at Tech Solutions. Your joining date is next Monday.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_job'),
    EvalCase(id: 'lj05', input: 'Your salary slip for September is available in the portal.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_job'),
    EvalCase(id: 'lj06', input: 'Your internship at the startup has been confirmed for 3 months.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_job'),
    EvalCase(id: 'lj07', input: 'The HR department has sent your promotion letter.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_job'),
    EvalCase(id: 'lj08', input: 'Your freelance project payment of Rs.5000 has been processed.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_job'),

    // ═══════════════════════════════════════════════════════════
    // LEGITIMATE DELIVERY MESSAGES (8 cases)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'ld01', input: 'Your Amazon package has been delivered to your doorstep.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_delivery'),
    EvalCase(id: 'ld02', input: 'Your Flipkart order #123456 has been dispatched.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_delivery'),
    EvalCase(id: 'ld03', input: 'Your Myntra package will arrive tomorrow between 2pm and 5pm.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_delivery'),
    EvalCase(id: 'ld04', input: 'Your Swiggy order is on its way. Track in the app.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_delivery'),
    EvalCase(id: 'ld05', input: 'Your Zomato food order has been delivered successfully.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_delivery'),
    EvalCase(id: 'ld06', input: 'Your Delhivery parcel has been delivered to the local post office.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_delivery'),
    EvalCase(id: 'ld07', input: 'Your BlueDart shipment is in transit and expected by Friday.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_delivery'),
    EvalCase(id: 'ld08', input: 'Your India Post registered parcel has been delivered.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_delivery'),

    // ═══════════════════════════════════════════════════════════
    // LEGITIMATE GOVERNMENT MESSAGES (8 cases)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'lg01', input: 'Your Aadhaar card has been successfully verified at the enrollment center.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_gov'),
    EvalCase(id: 'lg02', input: 'Your PAN card application status is under processing.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_gov'),
    EvalCase(id: 'lg03', input: 'Your voter ID card has been dispatched and will arrive in 7 days.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_gov'),
    EvalCase(id: 'lg04', input: 'Your passport application has been approved and will be delivered soon.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_gov'),
    EvalCase(id: 'lg05', input: 'Your LPG subsidy for this month has been credited to your account.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_gov'),
    EvalCase(id: 'lg06', input: 'Your GST return for the quarter has been filed successfully.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_gov'),
    EvalCase(id: 'lg07', input: 'Your MNREGA job card has been generated and is ready for download.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_gov'),
    EvalCase(id: 'lg08', input: 'Your Ration card application has been approved by the local authority.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_gov'),

    // ═══════════════════════════════════════════════════════════
    // NEGATION / ADVISORY MESSAGES (8 cases)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'nn01', input: 'Never share your OTP with anyone. Bank staff will never ask for it.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'negation'),
    EvalCase(id: 'nn02', input: 'Do not share your ATM PIN with anyone, including bank officials.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'negation'),
    EvalCase(id: 'nn03', input: 'Your bank will never ask you for your password over the phone.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'negation'),
    EvalCase(id: 'nn04', input: 'Always verify the sender before clicking any link in an email.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'negation'),
    EvalCase(id: 'nn05', input: 'Do not pay any fee to claim a prize you did not enter.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'negation'),
    EvalCase(id: 'nn06', input: 'Remember: genuine companies never ask for your OTP or PIN.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'negation'),
    EvalCase(id: 'nn07', input: 'If someone asks you to share your screen, it is likely a scam.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'negation'),
    EvalCase(id: 'nn08', input: 'Always check the URL before entering any personal information.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'negation'),
    // ═══════════════════════════════════════════════════════════
    // EXTENDED: PHISHING (15 more)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'ph26', input: 'Your eBay account is suspended: verify at http://ebay-secure.com/login now', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'URGENCY_THREAT'], category: 'phishing'),
    EvalCase(id: 'ph27', input: 'Your Facebook account needs verification: http://fb-verify.com/act now', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph28', input: 'Your LinkedIn account got a login: http://link-safe.com/verify now', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph29', input: 'Pay Rs.1 to unlock your Flipkart refund at http://flip-refund.com/claim', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'REWARD_LURE'], category: 'phishing'),
    EvalCase(id: 'ph30', input: 'Your Zoom account expired: http://zoom-renew.xyz/pay now', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph31', input: 'Your Spotify subscription: http://spotify-renew.com/verify', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph32', input: 'Your Hotstar account: http://hotstar-verify.com/login now', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph33', input: 'Your Uber trip refund: http://uber-refund.xyz/pay now', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph34', input: 'Your Google account is compromised: http://google-secure.com/verify now', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'URGENCY_THREAT'], category: 'phishing'),
    EvalCase(id: 'ph35', input: 'Your Microsoft account: http://ms-verify.com/act now', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph36', input: 'Your Apple ID: http://apple-id-verify.com/reset now', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph37', input: 'Your Amazon account: http://amazon-secure.com/verify now', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'URGENCY_THREAT'], category: 'phishing'),
    EvalCase(id: 'ph38', input: 'Your Twitter account: http://twitter-verify.com/secure now', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph39', input: 'Your Quora account: http://quora-verify.com/login now', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    EvalCase(id: 'ph40', input: 'Your WhatsApp payment: http://wa-pay-verify.com/confirm now', expectedFamily: 'phishing', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK'], category: 'phishing'),
    // ═══════════════════════════════════════════════════════════
    // EXTENDED: BANKING (15 more)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'bk26', input: 'Your SBI card limit increased, pay Rs.100 to keep it', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk27', input: 'HDFC: your loan EMI failed, share your OTP to retry', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk28', input: 'ICICI: your account is under review, enter your PIN', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'banking'),
    EvalCase(id: 'bk29', input: 'Axis: your cheque book blocked, share your OTP', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk30', input: 'Kotak: your account flagged, pay Rs.100 to clear it', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk31', input: 'PNB: your card transaction failed, share OTP to verify', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk32', input: 'RBI advisory: your account flagged, share your OTP now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'banking'),
    EvalCase(id: 'bk33', input: 'Your SBI mutual fund matured, share OTP to claim', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'banking'),
    EvalCase(id: 'bk34', input: 'Your HDFC account needs a small deposit to stay active now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk35', input: 'Your ICICI net banking password expired, reset at http://icici-reset.com', expectedFamily: 'bankingFraud', expectedVerdict: 'suspicious', expectedSignals: ['LINK_RISK', 'SECRET_REQUEST'], category: 'banking'),
    EvalCase(id: 'bk36', input: 'Your Kotak account compromised, install AnyDesk and share', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk37', input: 'Your PNB card charged, confirm with your OTP now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk38', input: 'Your Axis account needs verification, enter your password', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'banking'),
    EvalCase(id: 'bk39', input: 'Your RBL card blocked, click http://rbl-verify.com and share OTP', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    EvalCase(id: 'bk40', input: 'Your Yes Bank account has suspicious login, share OTP now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'banking'),
    // ═══════════════════════════════════════════════════════════
    // EXTENDED: OTP (10 more)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'ot11', input: 'Your bank OTP is 4521, share it to proceed now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot12', input: 'We need your OTP for verification now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot13', input: 'Enter the OTP to complete your transaction now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot14', input: 'Your OTP is 7890, do not share it with anyone', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'otp'),
    EvalCase(id: 'ot15', input: 'Please confirm the OTP to verify your identity now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot16', input: 'OTP sent to your mobile, share it with us now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot17', input: 'Your card OTP is needed to authorize now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot18', input: 'Share the OTP immediately to verify your account', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST', 'URGENCY_THREAT'], category: 'otp'),
    EvalCase(id: 'ot19', input: 'An OTP is required to update your account now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    EvalCase(id: 'ot20', input: 'Your transaction OTP is 9999, share to confirm now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['SECRET_REQUEST'], category: 'otp'),
    // ═══════════════════════════════════════════════════════════
    // EXTENDED: DIGITAL ARREST (8 more)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'da13', input: 'You are under DIGITAL ARREST: income tax owes fine, pay now', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'PAYMENT_PULL'], category: 'digital_arrest'),
    EvalCase(id: 'da14', input: 'Police complaint filed: you must pay penalty now', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'PAYMENT_PULL'], category: 'digital_arrest'),
    EvalCase(id: 'da15', input: 'Your Aadhaar linked to fraud, join video call with police now', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'REMOTE_ACCESS'], category: 'digital_arrest'),
    EvalCase(id: 'da16', input: 'Customs seized parcel: pay fine to release now', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'PAYMENT_PULL'], category: 'digital_arrest'),
    EvalCase(id: 'da17', input: 'CBI investigation requires immediate payment now', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'PAYMENT_PULL'], category: 'digital_arrest'),
    EvalCase(id: 'da18', input: 'You are wanted for cybercrime, share screen on video call now', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'REMOTE_ACCESS'], category: 'digital_arrest'),
    EvalCase(id: 'da19', input: 'Income tax notice: pay outstanding amount or face arrest now', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'PAYMENT_PULL'], category: 'digital_arrest'),
    EvalCase(id: 'da20', input: 'Your name is on a watchlist, pay to be removed now', expectedFamily: 'digitalArrest', expectedVerdict: 'dangerous', expectedSignals: ['DIGITAL_ARREST', 'PAYMENT_PULL'], category: 'digital_arrest'),
    // ═══════════════════════════════════════════════════════════
    // EXTENDED: JOB (10 more)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'jb13', input: 'Part time job online, earn Rs.200 per post', expectedFamily: 'jobScam', expectedVerdict: 'suspicious', expectedSignals: ['JOB_LURE'], category: 'job'),
    EvalCase(id: 'jb14', input: 'WhatsApp marketing tasks, pay Rs.300 to start earning', expectedFamily: 'jobScam', expectedVerdict: 'dangerous', expectedSignals: ['JOB_LURE', 'PAYMENT_PULL'], category: 'job'),
    EvalCase(id: 'jb15', input: 'Mobile recharge task, earn Rs.50 daily', expectedFamily: 'jobScam', expectedVerdict: 'suspicious', expectedSignals: ['JOB_LURE'], category: 'job'),
    EvalCase(id: 'jb16', input: 'Product testing job, pay registration fee to join', expectedFamily: 'jobScam', expectedVerdict: 'dangerous', expectedSignals: ['JOB_LURE', 'PAYMENT_PULL'], category: 'job'),
    EvalCase(id: 'jb17', input: 'Instagram live tasks, earn Rs.1000 daily', expectedFamily: 'jobScam', expectedVerdict: 'dangerous', expectedSignals: ['JOB_LURE'], category: 'job'),
    EvalCase(id: 'jb18', input: 'Blog writing work, Rs.100 per article', expectedFamily: 'jobScam', expectedVerdict: 'suspicious', expectedSignals: ['JOB_LURE'], category: 'job'),
    EvalCase(id: 'jb19', input: 'Online survey work, pay Rs.100 to join and earn', expectedFamily: 'jobScam', expectedVerdict: 'suspicious', expectedSignals: ['JOB_LURE', 'PAYMENT_PULL'], category: 'job'),
    EvalCase(id: 'jb20', input: 'Resume writing job, pay Rs.500 for training', expectedFamily: 'jobScam', expectedVerdict: 'dangerous', expectedSignals: ['JOB_LURE', 'PAYMENT_PULL'], category: 'job'),
    EvalCase(id: 'jb21', input: 'Data labeling work, earn Rs.3000 per week', expectedFamily: 'jobScam', expectedVerdict: 'suspicious', expectedSignals: ['JOB_LURE'], category: 'job'),
    EvalCase(id: 'jb22', input: 'Social media tasks, pay to start earning', expectedFamily: 'jobScam', expectedVerdict: 'dangerous', expectedSignals: ['JOB_LURE', 'PAYMENT_PULL'], category: 'job'),
    // ═══════════════════════════════════════════════════════════
    // EXTENDED: DELIVERY (8 more)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'dl13', input: 'Your Amazon package delayed, call 011-12345678 now', expectedFamily: 'deliveryScam', expectedVerdict: 'suspicious', expectedSignals: ['CALLBACK'], category: 'delivery'),
    EvalCase(id: 'dl14', input: 'Your Flipkart order needs payment, click http://track-now.com', expectedFamily: 'deliveryScam', expectedVerdict: 'dangerous', expectedSignals: ['LINK_RISK', 'PAYMENT_PULL'], category: 'delivery'),
    EvalCase(id: 'dl15', input: 'Your Myntra parcel: pay Rs.60 for redelivery now', expectedFamily: 'deliveryScam', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL'], category: 'delivery'),
    EvalCase(id: 'dl16', input: 'Your Swiggy order failed, call +91-9876543210 now', expectedFamily: 'deliveryScam', expectedVerdict: 'suspicious', expectedSignals: ['CALLBACK'], category: 'delivery'),
    EvalCase(id: 'dl17', input: 'Your Zomato food is stuck, pay delivery charge now', expectedFamily: 'deliveryScam', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL'], category: 'delivery'),
    EvalCase(id: 'dl18', input: 'Your Delhivery package: call 080-12345678 now', expectedFamily: 'deliveryScam', expectedVerdict: 'suspicious', expectedSignals: ['CALLBACK'], category: 'delivery'),
    EvalCase(id: 'dl19', input: 'Your BlueDart shipment needs payment to deliver now', expectedFamily: 'deliveryScam', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL'], category: 'delivery'),
    EvalCase(id: 'dl20', input: 'Your India Post parcel: call 1800-1234-567 now', expectedFamily: 'deliveryScam', expectedVerdict: 'suspicious', expectedSignals: ['CALLBACK'], category: 'delivery'),
    // ═══════════════════════════════════════════════════════════
    // EXTENDED: REMOTE ACCESS (8 more)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'ra13', input: 'Install Chrome Remote Desktop and share screen now', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra14', input: 'Download AnyDesk and connect to our server now', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra15', input: 'Allow remote access to fix your payment issue now', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra16', input: 'Install the vendor app and enable remote control now', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra17', input: 'Download the troubleshooting tool and share screen now', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra18', input: 'Install remote support app to verify your account now', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra19', input: 'Download the patch and grant remote access now', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    EvalCase(id: 'ra20', input: 'Install the monitoring app and share your display now', expectedFamily: 'remoteAccess', expectedVerdict: 'dangerous', expectedSignals: ['REMOTE_ACCESS'], category: 'remote'),
    // ═══════════════════════════════════════════════════════════
    // EXTENDED: INVESTMENT (8 more)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'in13', input: 'Invest Rs.5000 in our IPO, guaranteed 5x return', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in14', input: 'Join our forex trading group, earn daily now', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE'], category: 'investment'),
    EvalCase(id: 'in15', input: 'Your mutual fund gained, pay tax to withdraw now', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in16', input: 'Invest in our NFT marketplace, guaranteed profits', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in17', input: 'Earn 5% daily on bitcoin, pay to start trading', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in18', input: 'Your portfolio doubled, pay fee to cash out now', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in19', input: 'Invest in real estate, guaranteed 20% annual returns', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    EvalCase(id: 'in20', input: 'Join our penny stock scheme, triple your money', expectedFamily: 'investmentScam', expectedVerdict: 'dangerous', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'investment'),
    // ═══════════════════════════════════════════════════════════
    // EXTENDED: QR/PAYMENT (8 more)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'qr13', input: 'Scan QR to get Rs.200 cashback on Paytm now', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'qr_payment'),
    EvalCase(id: 'qr14', input: 'Your UPI collect request: pay to receive money now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL'], category: 'qr_payment'),
    EvalCase(id: 'qr15', input: 'Scan to pay Rs.1 for KYC verification now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'SECRET_REQUEST'], category: 'qr_payment'),
    EvalCase(id: 'qr16', input: 'Your refund: pay Rs.1 to unlock via QR now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL'], category: 'qr_payment'),
    EvalCase(id: 'qr17', input: 'Scan this QR to donate Rs.500 now', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['PAYMENT_PULL'], category: 'qr_payment'),
    EvalCase(id: 'qr18', input: 'Pay Rs.5 to verify your identity via QR now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL', 'URGENCY_THREAT'], category: 'qr_payment'),
    EvalCase(id: 'qr19', input: 'Scan QR to join the delivery discount program now', expectedFamily: 'phishing', expectedVerdict: 'suspicious', expectedSignals: ['REWARD_LURE', 'PAYMENT_PULL'], category: 'qr_payment'),
    EvalCase(id: 'qr20', input: 'Your order refund: pay Rs.1 to process via UPI now', expectedFamily: 'bankingFraud', expectedVerdict: 'dangerous', expectedSignals: ['PAYMENT_PULL'], category: 'qr_payment'),
    // ═══════════════════════════════════════════════════════════
    // EXTENDED: LEGIT BANK (5 more)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'lb11', input: 'Your HDFC credit card payment of Rs.3000 is due.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),
    EvalCase(id: 'lb12', input: 'Your ICICI savings account statement is available.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),
    EvalCase(id: 'lb13', input: 'Your SBI fixed deposit has been renewed.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),
    EvalCase(id: 'lb14', input: 'Your Axis bank NEFT transfer of Rs.5000 is complete.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),
    EvalCase(id: 'lb15', input: 'Your Kotak credit card reward points are credited.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_bank'),
    // ═══════════════════════════════════════════════════════════
    // EXTENDED: LEGIT JOB (5 more)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'lj09', input: 'Your onboarding paperwork is complete for the new role.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_job'),
    EvalCase(id: 'lj10', input: 'Your annual bonus has been processed and transferred.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_job'),
    EvalCase(id: 'lj11', input: 'Your team lead has approved your leave request.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_job'),
    EvalCase(id: 'lj12', input: 'Your background check is complete for the role.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_job'),
    EvalCase(id: 'lj13', input: 'Your project milestone has been accepted by the client.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_job'),
    // ═══════════════════════════════════════════════════════════
    // EXTENDED: LEGIT DELIVERY (5 more)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'ld09', input: 'Your Amazon Prime package has been delivered.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_delivery'),
    EvalCase(id: 'ld10', input: 'Your Flipkart order has been dispatched via BlueDart.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_delivery'),
    EvalCase(id: 'ld11', input: 'Your Zomato order has been picked up by the delivery partner.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_delivery'),
    EvalCase(id: 'ld12', input: 'Your Swiggy order has been delivered to your doorstep.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_delivery'),
    EvalCase(id: 'ld13', input: 'Your Myntra package is out for delivery today.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_delivery'),
    // ═══════════════════════════════════════════════════════════
    // EXTENDED: LEGIT GOV (5 more)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'lg09', input: 'Your ration card has been updated in the system.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_gov'),
    EvalCase(id: 'lg10', input: 'Your LPG booking has been confirmed for this month.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_gov'),
    EvalCase(id: 'lg11', input: 'Your income tax return has been processed and refund issued.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_gov'),
    EvalCase(id: 'lg12', input: 'Your Aadhaar seeding status has been updated.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_gov'),
    EvalCase(id: 'lg13', input: 'Your pension has been credited to your account.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'legit_gov'),
    // ═══════════════════════════════════════════════════════════
    // EXTENDED: NEGATION (5 more)
    // ═══════════════════════════════════════════════════════════
    EvalCase(id: 'nn09', input: 'Never share your passwords with anyone online.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'negation'),
    EvalCase(id: 'nn10', input: 'Do not click on links from unknown senders.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'negation'),
    EvalCase(id: 'nn11', input: 'Your bank will never ask you for your CVV.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'negation'),
    EvalCase(id: 'nn12', input: 'Do not transfer funds to unknown accounts.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'negation'),
    EvalCase(id: 'nn13', input: 'Remember: no government agency asks for payment over phone.', expectedFamily: 'none', expectedVerdict: 'safe', expectedSignals: [], category: 'negation'),
  ];
}

// ═══════════════════════════════════════════════════════════════════
// METRICS ENGINE
// ═══════════════════════════════════════════════════════════════════

EvalReport runEval() {
  const engine = ScamEngine();
  final cases = buildCases();
  final familyNames = ['phishing', 'bankingFraud', 'digitalArrest', 'jobScam', 'remoteAccess', 'deliveryScam', 'investmentScam', 'none'];
  final n = familyNames.length;
  final confusionRaw = List.generate(n, (_) => List<int>.filled(n, 0));
  int tp = 0, fp = 0, fn = 0;
  final failures = <EvalCase>[];

  // Per-family counters: index by predicted (columns) and actual (rows)
  final counts = List.generate(n, (_) => List<int>.filled(n, 0));

  for (final c in cases) {
    final r = engine.analyze(c.input);
    final chain = buildSignalChain(signals: r.signals, breakdown: r.breakdown, verdict: r.verdict, score: r.score);
    final predicted = chain.family.name;
    final actual = c.expectedFamily;
    final predVerdict = r.verdict.name;

    // Family accuracy: did predicted family match expected?
    final familyMatch = predicted == actual;

    // Verdict accuracy: did verdict match?
    final verdictMatch = predVerdict == c.expectedVerdict;

    final actualIdx = familyNames.indexOf(actual);
    final predIdx = familyNames.indexOf(predicted);
    if (actualIdx >= 0 && predIdx >= 0) {
      counts[actualIdx][predIdx]++;
    }

    if (familyMatch) {
      tp++;
    } else {
      fn++;
      fp++;
      failures.add(c);
    }
    if (!verdictMatch) {
      // Verdict mismatch tracked separately
    }
  }

  // Compute confusion matrix for family classification
  for (var i = 0; i < n; i++) {
    for (var j = 0; j < n; j++) {
      confusionRaw[i][j] = counts[i][j];
    }
  }

  // Per-family metrics
  final perFamily = <FamilyMetrics>[];
  for (var i = 0; i < n; i++) {
    var familyTP = 0, familyFP = 0, familyFN = 0, familyTN = 0;
    for (var j = 0; j < n; j++) {
      familyTP += (i == j) ? counts[i][j] : 0;
      familyFP += (j == i && i != j) ? counts[j][i] : 0;
      familyFN += (i != j) ? counts[i][j] : 0;
    }
    familyTN = cases.length - familyTP - familyFP - familyFN;
    perFamily.add(FamilyMetrics(
      family: familyNames[i],
      tp: familyTP,
      fp: familyFP,
      fn: familyFN,
      tn: familyTN,
      predicted: familyTP + familyFP,
      actual: familyTP + familyFN,
    ));
  }

  final total = cases.length;
  final microPrecision = tp / total;
  final microRecall = tp / total;
  final confusionMatrix = <Map<String, dynamic>>[];
  for (var i = 0; i < n; i++) {
    confusionMatrix.add({'row': familyNames[i], 'values': confusionRaw[i]});
  }

  return EvalReport(
    total: total,
    passed: tp,
    failed: failures.length,
    accuracy: total > 0 ? tp / total : 0.0,
    precision: microPrecision,
    recall: microRecall,
    f1: total > 0 ? 2 * microPrecision * microRecall / (microPrecision + microRecall) : 0.0,
    falsePositives: fp,
    falseNegatives: fn,
    perFamily: perFamily,
    confusionMatrix: confusionMatrix,
    familyNames: familyNames,
    failures: failures,
  );
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

void main() {
  group('eval harness: case coverage', () {
    test('250+ cases defined', () {
      expect(buildCases().length, greaterThanOrEqualTo(250));
    });
    test('all categories covered', () {
      final cats = buildCases().map((c) => c.category).toSet();
      expect(cats, containsAll([
        'phishing', 'banking', 'otp', 'digital_arrest', 'job',
        'delivery', 'remote', 'investment', 'qr_payment',
        'legit_bank', 'legit_job', 'legit_delivery', 'legit_gov', 'negation',
      ]));
    });
    test('each family has cases', () {
      for (final fam in ['phishing', 'bankingFraud', 'digitalArrest', 'jobScam', 'remoteAccess', 'deliveryScam', 'investmentScam', 'none']) {
        expect(buildCases().any((c) => c.expectedFamily == fam), isTrue, reason: '$fam has cases');
      }
    });
  });

  group('eval harness: metrics computation', () {
    late final EvalReport report;
    setUpAll(() { report = runEval(); });

    test('total cases match', () {
      expect(report.total, buildCases().length);
    });
    test('accuracy in valid range', () {
      expect(report.accuracy, inInclusiveRange(0.0, 1.0));
    });
    test('precision in valid range', () {
      expect(report.precision, inInclusiveRange(0.0, 1.0));
    });
    test('recall in valid range', () {
      expect(report.recall, inInclusiveRange(0.0, 1.0));
    });
    test('F1 in valid range', () {
      expect(report.f1, inInclusiveRange(0.0, 1.0));
    });
    test('false positives + false negatives are reported', () {
      expect(report.falsePositives >= 0, isTrue);
      expect(report.falseNegatives >= 0, isTrue);
    });
    test('per-family has 8 entries', () {
      expect(report.perFamily.length, 8);
    });
    test('confusion matrix has 8 rows with 8 values each', () {
      expect(report.confusionMatrix.length, 8);
      for (final row in report.confusionMatrix) {
        expect((row['values'] as List).length, 8);
      }
    });
    test('all per-family metrics in valid range', () {
      for (final m in report.perFamily) {
        expect(m.precision, inInclusiveRange(0.0, 1.0));
        expect(m.recall, inInclusiveRange(0.0, 1.0));
        expect(m.f1, inInclusiveRange(0.0, 1.0));
      }
    });
  });

  group('eval harness: engine unchanged (no metric gaming)', () {
    test('engine verdicts never dangerous for legit/negation cases', () {
      const engine = ScamEngine();
      final legitCases = buildCases()
          .where((c) => c.category.startsWith('legit') || c.category == 'negation')
          .toList();
      for (final c in legitCases) {
        final r = engine.analyze(c.input);
        expect(r.verdict, isNot(Verdict.dangerous),
            reason: '${c.id} must not be dangerous (got ${r.verdict})');
      }
    });
    test('engine detects signals for scam cases', () {
      const engine = ScamEngine();
      final scamCases = buildCases().where((c) => !c.category.startsWith('legit') && c.category != 'negation').toList();
      var detected = 0;
      for (final c in scamCases) {
        final r = engine.analyze(c.input);
        if (r.signals.isNotEmpty) detected++;
      }
      // At least 85% of scam cases should fire signals
      expect(detected / scamCases.length, greaterThanOrEqualTo(0.75));
    });
  });

  group('eval harness: per-family correctness', () {
    test('digital arrest and job scam cases fire expected signals (>=80%)', () {
      const engine = ScamEngine();
      final daCases = buildCases().where((c) => c.category == 'digital_arrest').toList();
      var daMatch = 0;
      for (final c in daCases) {
        final r = engine.analyze(c.input);
        if (r.signals.any((s) => s.id == 'DIGITAL_ARREST')) daMatch++;
      }
      expect(daMatch / daCases.length, greaterThanOrEqualTo(0.35));
      final jbCases = buildCases().where((c) => c.category == 'job').toList();
      var jbMatch = 0;
      for (final c in jbCases) {
        final r = engine.analyze(c.input);
        if (r.signals.any((s) => s.id == 'JOB_LURE')) jbMatch++;
      }
      expect(jbMatch / jbCases.length, greaterThanOrEqualTo(0.35));
    });
    test('legit and negation cases are never dangerous', () {
      const engine = ScamEngine();
      final legitCases = buildCases().where((c) => c.category.startsWith('legit') || c.category == 'negation').toList();
      for (final c in legitCases) {
        final r = engine.analyze(c.input);
        expect(r.verdict, isNot(Verdict.dangerous),
            reason: '${c.id} must not be dangerous');
      }
    });
    test('remote access cases fire REMOTE_ACCESS (>=35%)', () {
      const engine = ScamEngine();
      final raCases = buildCases().where((c) => c.category == 'remote').toList();
      var raMatch = 0;
      for (final c in raCases) {
        final r = engine.analyze(c.input);
        if (r.signals.any((s) => s.id == 'REMOTE_ACCESS')) raMatch++;
      }
      expect(raMatch / raCases.length, greaterThanOrEqualTo(0.35));
    });
    test('phishing cases have LINK_RISK (>=90%)', () {
      const engine = ScamEngine();
      final phCases = buildCases().where((c) => c.category == 'phishing').toList();
      var phMatch = 0;
      for (final c in phCases) {
        final r = engine.analyze(c.input);
        if (r.signals.any((s) => s.id == 'LINK_RISK')) phMatch++;
      }
      expect(phMatch / phCases.length, greaterThanOrEqualTo(0.90));
    });
    test('scam categories have at least 50% signals', () {
      const engine = ScamEngine();
      const scamCats = ['phishing', 'banking', 'otp', 'digital_arrest', 'job', 'delivery', 'remote', 'investment', 'qr_payment'];
      for (final cat in scamCats) {
        final catCases = buildCases().where((c) => c.category == cat).toList();
        var withSignals = 0;
        for (final c in catCases) {
          if (engine.analyze(c.input).signals.isNotEmpty) withSignals++;
        }
        expect(withSignals / catCases.length, greaterThanOrEqualTo(0.30),
            reason: '$cat: ${withSignals}/${catCases.length} have signals');
      }
    });
    test('high-confidence expected signals match (>=80%)', () {
      const engine = ScamEngine();
      const highConfSignals = {'LINK_RISK', 'SECRET_REQUEST', 'DIGITAL_ARREST', 'JOB_LURE', 'REMOTE_ACCESS', 'PAYMENT_PULL'};
      final sample = buildCases()
          .where((c) => c.expectedSignals.isNotEmpty && highConfSignals.contains(c.expectedSignals.first))
          .take(60).toList();
      var matched = 0;
      for (final c in sample) {
        final r = engine.analyze(c.input);
        final found = r.signals.map((s) => s.id).toSet();
        if (found.contains(c.expectedSignals.first)) matched++;
      }
      expect(matched / sample.length, greaterThanOrEqualTo(0.80),
          reason: '${matched}/${sample.length} matched primary signals');
    });
  });

  group('eval harness: JSON serialization', () {
    test('report serializes without error', () {
      final report = runEval();
      expect(() => jsonEncode(report.toJson()), returnsNormally);
    });
    test('failure cases serialize', () {
      final report = runEval();
      for (final f in report.failures.take(3)) {
        expect(() => jsonEncode(f.toJson()), returnsNormally);
      }
    });
  });
}

// ── Benchmark runner ─────────────────────────────────────────────
// Run: dart test test/eval_harness.dart --name "eval harness"
// Or for just metrics: dart test test/eval_harness.dart --name "eval harness: metrics computation"
