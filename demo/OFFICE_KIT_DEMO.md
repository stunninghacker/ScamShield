# ScamShield Demo — Office Kit Workflow (Phone → Laptop)

No automatic sync is claimed or required. This is the reliable manual bridge
used live on stage (2:20–2:40 in the 3-minute demo).

## What Office Kit actually does here

Phone (sensor + protection) → Office Kit clipboard/file transfer → Laptop
(display + analysis surface). ScamShield contributes the structured threat
event; Office Kit contributes the transport.

## Steps (rehearse once)

1. **Phone:** run any scan (e.g. Demo Mode → Fake KYC). Note the event.
2. **Phone → Command Center → Export** (upload icon): copies the event log
   as JSON to the clipboard.
3. **Office Kit:** paste/send the clipboard text (or a saved `.json` file)
   to the laptop, exactly as you would forward any demo artifact.
4. **Laptop:** open ScamShield (Chrome: `flutter run -d chrome`) →
   Command Center → **Import** (download icon) → paste → Import.
5. **Laptop:** the phone's HIGH event appears in the feed with category,
   signals, score and recommended action. Tap it for the evidence sheet.

## Spoken line (20 seconds)

> "The phone stays the sensor — camera, SMS, analysis, all offline. The
> laptop becomes the analyst's desk: same structured event, signals and
> recommended action, moved over Office Kit. No servers, no accounts."

## Fallbacks (in order)

1. Clipboard via Office Kit (primary).
2. Save JSON to a file → Office Kit file transfer → Import.
3. Skip the laptop: Command Center on the phone shows the identical feed.
