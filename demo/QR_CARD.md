# ScamShield Demo — Printed QR Card

Projector QRs often fail (glare, focus, refresh rate). Print this card as the
**primary** QR demo. The in-app *Sample QR* button remains the fallback.

## Payload (deterministic, safe — no real payee, no real link)

```text
upi://pay?pa=refund-cell@okhdfcbank&pn=KYC%20Refund&am=999
```

Generate the QR with any offline generator (or `qrencode -o qr.png
'upi://pay?pa=refund-cell@okhdfcbank&pn=KYC%20Refund&am=999'`) and print it
below the header.

## Card layout (A6 or half-letter)

```text
┌─────────────────────────────────┐
│  SCAMSHIELD DEMO                │
│  Fake KYC Payment Request       │
│                                 │
│  [QR goes here — 5×5 cm min]    │
│                                 │
│  "Scan to receive your refund"  │
│  — the scammer's lie            │
└─────────────────────────────────┘
```

## Expected result when scanned

- Banner: **⚠️ POTENTIAL PAYMENT SCAM** (HIGH)
- Kind: UPI payment request → payee `refund-cell@okhdfcbank`, ₹999
- Note: *"This QR ASKS YOU to pay… Anyone saying 'scan to RECEIVE money'
  is lying: scanning can only SEND."*
- Actions: Analyze again / Verify

## Spoken line (15 seconds)

> "The message says scan to *receive* your refund. The QR actually *requests*
> ₹999 from you. Receiving versus requesting — that mismatch is the scam, and
> ScamShield shows it before anyone pays."
