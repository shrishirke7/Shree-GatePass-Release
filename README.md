# Shree GatePass · Standalone Visitor & Material Gate Management

A dedicated, lightweight, zero-bloat standalone application for:
- **Visitor Pass Lifecycle**: Gate Entry (`Pending`) → User / Dept Approval (`Approved` / `Rejected`) → Host/Gate `Check In` (`Checked In`) → `Check Out` (`Checked Out`).
- **Strict Targeted Notifications**:
  - When a specific **Host User** is selected, only that exact user receives notifications, ringtones, live alerts, and inbox items.
  - When **Anyone in Department** is selected (Host left blank), all enabled users in that department receive the alert — other departments do not.
- **Material Gate Pass (IN / OUT) & Returnable Tracker**: Records inward & outward materials with multi-page challan/bill photos & material photos (native mobile camera + browser capture) and automatic due-date overdue notifications.
- **Standalone Organization Controls**: Users (with Excel/CSV bulk import & export), Departments, Factories (with location descriptions), Custom Ringtones & Silent Schedules, Scheduled Database/Photo Backups, Android APK (`com.shree.gatepass`), and Apple `.mobileconfig` / iOS Xcode project.

## Quick Ubuntu Installation (Runs Alongside Existing Apps on Port 8858/8859)

```bash
unzip Shree-GatePass-Release.zip -d shree-gatepass-installer
cd shree-gatepass-installer
sudo bash install.sh
```

Default ports:
- **HTTPS (Recommended for Camera & Notifications)**: `https://<server-ip>:8859`
- **HTTP**: `http://<server-ip>:8858`
- **Security Gate Kiosk (No Login)**: `https://<server-ip>:8859/portal`
