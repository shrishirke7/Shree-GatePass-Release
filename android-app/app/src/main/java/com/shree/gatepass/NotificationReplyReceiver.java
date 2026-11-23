package com.shree.gatepass;

import android.app.RemoteInput;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.CookieManager;

import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

public class NotificationReplyReceiver extends BroadcastReceiver {
    public static final String ACTION_STILL_INSIDE = "com.shree.gatepass.ACTION_STILL_INSIDE";
    public static final String ACTION_MARK_LEFT = "com.shree.gatepass.ACTION_MARK_LEFT";
    public static final String KEY_REPLY_REASON = "stay_reply_reason";
    public static final String EXTRA_VISITOR_ID = "extra_visitor_id";
    public static final String EXTRA_NOTIF_ID = "extra_notif_id";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();
        String visitorId = intent.getStringExtra(EXTRA_VISITOR_ID);
        int notifId = intent.getIntExtra(EXTRA_NOTIF_ID, 0);
        if (visitorId == null || visitorId.isEmpty()) return;

        final boolean isLeft = ACTION_MARK_LEFT.equals(action);
        String reason = "";
        Bundle results = RemoteInput.getResultsFromIntent(intent);
        if (results != null) {
            CharSequence seq = results.getCharSequence(KEY_REPLY_REASON);
            if (seq != null) reason = seq.toString().trim();
        }
        final String finalReason = reason;
        final PendingResult pendingResult = goAsync();
        final Context appCtx = context.getApplicationContext();

        new Thread(() -> {
            try {
                String baseUrl = CertPinStore.getServerUrl(appCtx);
                if (baseUrl.isEmpty()) {
                    NotificationHelper.showConfirmation(appCtx, notifId, "Open Shree GatePass", "Server URL missing — tap to update " + visitorId, visitorId);
                    return;
                }
                Uri parsed = Uri.parse(baseUrl);
                String origin = parsed.getScheme() + "://" + parsed.getAuthority();
                URL url = new URL(origin + "/api/visitors/" + Uri.encode(visitorId) + "/stay-response");

                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(6000);
                conn.setReadTimeout(6000);
                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
                conn.setRequestProperty("X-Requested-With", "ShreeGatePass");

                if (conn instanceof HttpsURLConnection) {
                    String host = url.getHost();
                    SSLSocketFactory sf = CertPinStore.buildPinnedSslSocketFactory(appCtx, host);
                    HostnameVerifier hv = CertPinStore.buildPinnedHostnameVerifier(appCtx, host);
                    if (sf != null) ((HttpsURLConnection) conn).setSSLSocketFactory(sf);
                    if (hv != null) ((HttpsURLConnection) conn).setHostnameVerifier(hv);
                }

                try {
                    String cookie = CookieManager.getInstance().getCookie(origin);
                    if (cookie != null && !cookie.isEmpty()) {
                        conn.setRequestProperty("Cookie", cookie);
                    }
                } catch (Exception ignored) {
                }

                JSONObject body = new JSONObject();
                body.put("action", isLeft ? "left" : "still_inside");
                body.put("reason", isLeft
                        ? (finalReason.isEmpty() ? "Marked left from Android notification bar" : finalReason)
                        : (finalReason.isEmpty() ? "Work / meeting still in progress" : finalReason));
                body.put("extendMinutes", 30);

                byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(bytes);
                }

                int code = conn.getResponseCode();
                conn.disconnect();

                if (code >= 200 && code < 300) {
                    String msg = isLeft
                            ? "Visitor checked out (" + visitorId + ")"
                            : "Saved: " + (finalReason.isEmpty() ? "Still Inside (+30m)" : finalReason);
                    NotificationHelper.showConfirmation(appCtx, notifId, "✓ Status Updated", msg, visitorId);
                } else {
                    NotificationHelper.showAlert(
                            appCtx,
                            "Update needed in app",
                            "Could not send reply (HTTP " + code + "). Tap to open " + visitorId,
                            "visitors",
                            visitorId,
                            "visitor_stay_check"
                    );
                }
            } catch (Exception e) {
                NotificationHelper.showAlert(
                        appCtx,
                        "Reply offline — tap to open",
                        "Tap to update visitor " + visitorId + " inside Shree GatePass",
                        "visitors",
                        visitorId,
                        "visitor_stay_check"
                );
            } finally {
                pendingResult.finish();
            }
        }).start();
    }
}
