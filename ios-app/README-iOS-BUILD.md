# Shree GatePass — iPhone & iPad Installation Guide

## Option 1: Instant 1-Tap Install Without a Mac (Recommended)
1. Open Safari on your iPhone or iPad and visit `https://<your-server>:8859` (or `http://<your-server>:8858`).
2. Tap **Install Mobile App (Android APK & iPhone/iPad)** → **Install on iPhone / iPad (.mobileconfig)**.
3. Allow the profile download, then open **Settings → General → VPN & Device Management → Shree GatePass** and tap **Install**.
4. The **Shree GatePass** app appears on your Home Screen and launches full-screen with camera capture and targeted gate alerts.

## Option 2: Native Xcode Project Build (`com.shree.gatepass`)
1. Copy the `ios-app` folder to any Mac with Xcode 15+ (or push to GitHub to run `.github/workflows/build-gatepass-ios.yml`).
2. Open `ShreeGatePass.xcodeproj`, select your Apple Team under **Signing & Capabilities**, and build to any iPhone or iPad (iOS 15.0+, `TARGETED_DEVICE_FAMILY = "1,2"`).
