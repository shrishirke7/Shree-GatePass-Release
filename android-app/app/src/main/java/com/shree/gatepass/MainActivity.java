package com.shree.gatepass;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.DownloadManager;
import android.content.ClipData;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Matrix;
import android.media.ExifInterface;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Base64;
import android.view.View;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.PermissionRequest;
import android.webkit.SslErrorHandler;
import android.webkit.URLUtil;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends Activity {
    public static volatile boolean isAppInForeground = false;
    private static final int REQ_FILE_CHOOSER = 5001;
    private static final int REQ_STARTUP_PERM = 5002;
    private static final int REQ_CAMERA_PERM = 5003;
    private static final int REQ_CAMERA_CHOOSER = 5004;
    private static final int REQ_CAMERA_NATIVE = 5005;
    private static final int REQ_NATIVE_CAMERA = 5006;

    private WebView webView;
    private ProgressBar progressBar;
    private LinearLayout errorView;
    private TextView errorDetailText;

    private ValueCallback<Uri[]> fileUploadCallback = null;
    private PermissionRequest pendingPermissionRequest = null;
    private String[] pendingGrantResources = null;
    private WebChromeClient.FileChooserParams pendingChooserParams = null;
    private Uri pendingCameraPhotoUri = null;
    private File pendingCameraPhotoFile = null;
    private String pendingNativeFacing = "environment";
    private String pendingNativeCallbackFn = "";
    private File pendingNativePhotoFile = null;
    private boolean sslDialogShowing = false;
    private final List<SslErrorHandler> pendingSslHandlers = new ArrayList<>();
    private String configuredHost = "";

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String serverUrl = CertPinStore.getServerUrl(this);
        if (serverUrl.isEmpty()) {
            startActivity(new Intent(this, ServerSetupActivity.class));
            finish();
            return;
        }

        Uri parsed = Uri.parse(serverUrl);
        configuredHost = parsed != null && parsed.getHost() != null ? parsed.getHost() : "";

        setContentView(R.layout.activity_main);
        webView = findViewById(R.id.webView);
        progressBar = findViewById(R.id.progressBar);
        errorView = findViewById(R.id.errorView);
        errorDetailText = findViewById(R.id.errorDetailText);
        Button retryBtn = findViewById(R.id.retryBtn);
        Button changeServerBtn = findViewById(R.id.changeServerBtn);

        retryBtn.setOnClickListener(v -> {
            errorView.setVisibility(View.GONE);
            webView.setVisibility(View.VISIBLE);
            webView.reload();
        });
        changeServerBtn.setOnClickListener(v -> startActivity(new Intent(this, ServerSetupActivity.class)));

        NotificationHelper.ensureChannels(this);
        requestStartupPermissionsIfNeeded();
        setupWebView(serverUrl);
    }

    private void requestStartupPermissionsIfNeeded() {
        if (Build.VERSION.SDK_INT < 23) return;
        List<String> needed = new ArrayList<>();
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            needed.add(Manifest.permission.POST_NOTIFICATIONS);
        }
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            needed.add(Manifest.permission.CAMERA);
        }
        if (!needed.isEmpty()) {
            requestPermissions(needed.toArray(new String[0]), REQ_STARTUP_PERM);
        }
    }

    private void startMonitorServiceIfEnabled() {
        if (!CertPinStore.isBgAlertsEnabled(this)) return;
        try {
            Intent svc = new Intent(this, AlertMonitorService.class);
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(svc);
            else startService(svc);
        } catch (Exception ignored) {
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private void setupWebView(String initialUrl) {
        CookieManager cm = CookieManager.getInstance();
        cm.setAcceptCookie(true);
        cm.setAcceptThirdPartyCookies(webView, true);

        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        s.setAllowFileAccess(true);
        s.setMediaPlaybackRequiresUserGesture(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE);
        s.setLoadWithOverviewMode(true);
        s.setUseWideViewPort(true);
        s.setSupportZoom(false);
        webView.setLayerType(View.LAYER_TYPE_HARDWARE, null);
        webView.setOverScrollMode(View.OVER_SCROLL_IF_CONTENT_SCROLLS);

        webView.addJavascriptInterface(new ShreeBridge(), "ShreeAndroid");

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (uri == null) return false;
                String host = uri.getHost();
                if (host != null && (host.equalsIgnoreCase(configuredHost) || configuredHost.isEmpty())) {
                    return false;
                }
                try {
                    startActivity(new Intent(Intent.ACTION_VIEW, uri));
                    return true;
                } catch (Exception e) {
                    return false;
                }
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                CookieManager.getInstance().flush();
                progressBar.setVisibility(View.GONE);
                startMonitorServiceIfEnabled();
                handleDeepLinkIntent(getIntent());
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                super.onReceivedError(view, request, error);
                if (request != null && request.isForMainFrame()) {
                    webView.setVisibility(View.GONE);
                    errorView.setVisibility(View.VISIBLE);
                    if (error != null && Build.VERSION.SDK_INT >= 23 && error.getDescription() != null) {
                        errorDetailText.setText("Server: " + initialUrl + "\nError: " + error.getDescription());
                    }
                }
            }

            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                X509Certificate x509 = CertPinStore.extractX509(error.getCertificate());
                String fp = CertPinStore.sha256Fingerprint(x509);
                Uri errUri = Uri.parse(error.getUrl());
                String errHost = errUri != null && errUri.getHost() != null ? errUri.getHost() : configuredHost;

                if (!fp.isEmpty() && CertPinStore.isCertPinned(MainActivity.this, errHost, fp)) {
                    handler.proceed();
                    return;
                }

                synchronized (pendingSslHandlers) {
                    pendingSslHandlers.add(handler);
                    if (sslDialogShowing) return;
                    sslDialogShowing = true;
                }
                runOnUiThread(() -> showSslTrustDialog(errHost, fp));
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                if (newProgress < 100) {
                    progressBar.setVisibility(View.VISIBLE);
                    progressBar.setProgress(newProgress);
                } else {
                    progressBar.setVisibility(View.GONE);
                }
            }

            @Override
            public void onPermissionRequest(PermissionRequest request) {
                runOnUiThread(() -> {
                    String[] resources = request.getResources();
                    List<String> requested = new ArrayList<>();
                    List<String> neededPerms = new ArrayList<>();
                    for (String res : resources) {
                        if (PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(res)) {
                            requested.add(res);
                            if (Build.VERSION.SDK_INT >= 23 && checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                                neededPerms.add(Manifest.permission.CAMERA);
                            }
                        }
                    }
                    if (requested.isEmpty()) {
                        request.deny();
                        return;
                    }
                    if (!neededPerms.isEmpty() && Build.VERSION.SDK_INT >= 23) {
                        pendingPermissionRequest = request;
                        pendingGrantResources = requested.toArray(new String[0]);
                        requestPermissions(neededPerms.toArray(new String[0]), REQ_CAMERA_PERM);
                    } else {
                        request.grant(requested.toArray(new String[0]));
                    }
                });
            }

            @Override
            public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> filePathCallback, FileChooserParams fileChooserParams) {
                if (fileUploadCallback != null) fileUploadCallback.onReceiveValue(null);
                fileUploadCallback = filePathCallback;
                if (acceptsImageTypes(fileChooserParams)
                        && Build.VERSION.SDK_INT >= 23
                        && checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                    pendingChooserParams = fileChooserParams;
                    requestPermissions(new String[]{Manifest.permission.CAMERA}, REQ_CAMERA_CHOOSER);
                    return true;
                }
                launchFileChooserWithCamera(fileChooserParams);
                return true;
            }
        });

        webView.setDownloadListener((url, userAgent, contentDisposition, mimetype, contentLength) -> {
            try {
                DownloadManager.Request req = new DownloadManager.Request(Uri.parse(url));
                if (mimetype != null) req.setMimeType(mimetype);
                String cookies = CookieManager.getInstance().getCookie(url);
                if (cookies != null) req.addRequestHeader("Cookie", cookies);
                req.addRequestHeader("User-Agent", userAgent);
                String fileName = URLUtil.guessFileName(url, contentDisposition, mimetype);
                req.setTitle(fileName);
                req.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
                req.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, fileName);
                DownloadManager dm = (DownloadManager) getSystemService(DOWNLOAD_SERVICE);
                if (dm != null) {
                    dm.enqueue(req);
                    Toast.makeText(this, "Downloading " + fileName, Toast.LENGTH_SHORT).show();
                }
            } catch (Exception e) {
                try { startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url))); } catch (Exception ignored) {}
            }
        });

        webView.loadUrl(initialUrl);
    }

    private void showSslTrustDialog(String host, String fp) {
        String msg = "Your GatePass server presented a private SSL certificate:\n\n"
                + "Host: " + host + "\n"
                + "SHA-256: " + (fp.isEmpty() ? "(unavailable)" : fp) + "\n\n"
                + "Trust & pin this certificate automatically?";
        new AlertDialog.Builder(this)
                .setTitle("Trust GatePass Server?")
                .setMessage(msg)
                .setCancelable(false)
                .setPositiveButton("Trust & Connect", (d, w) -> {
                    if (!fp.isEmpty()) CertPinStore.savePinnedCert(MainActivity.this, host, fp);
                    synchronized (pendingSslHandlers) {
                        for (SslErrorHandler h : pendingSslHandlers) h.proceed();
                        pendingSslHandlers.clear();
                        sslDialogShowing = false;
                    }
                })
                .setNegativeButton("Cancel", (d, w) -> {
                    synchronized (pendingSslHandlers) {
                        for (SslErrorHandler h : pendingSslHandlers) h.cancel();
                        pendingSslHandlers.clear();
                        sslDialogShowing = false;
                    }
                })
                .show();
    }

    private void handleDeepLinkIntent(Intent intent) {
        if (intent == null || webView == null) return;
        String targetView = intent.getStringExtra("targetView");
        if (targetView != null && !targetView.isEmpty()) {
            intent.removeExtra("targetView");
            intent.removeExtra("targetId");
            String js = "if(typeof window.switchView==='function'){window.switchView(" + JSONObject.quote(targetView) + ");}";
            webView.evaluateJavascript(js, null);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleDeepLinkIntent(intent);
    }

    @Override
    protected void onResume() {
        super.onResume();
        isAppInForeground = true;
    }

    @Override
    protected void onPause() {
        super.onPause();
        isAppInForeground = false;
        CookieManager.getInstance().flush();
    }

    private boolean acceptsImageTypes(WebChromeClient.FileChooserParams params) {
        if (params == null || params.getAcceptTypes() == null) return false;
        for (String t : params.getAcceptTypes()) {
            if (t != null && (t.contains("image") || t.contains(".jpg") || t.contains(".jpeg") || t.contains(".png"))) return true;
        }
        return false;
    }

    private void grantUriPermissionsForIntent(Intent intent, Uri uri) {
        try {
            List<ResolveInfo> resInfos = getPackageManager().queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY);
            for (ResolveInfo ri : resInfos) {
                grantUriPermission(ri.activityInfo.packageName, uri, Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_READ_URI_PERMISSION);
            }
        } catch (Exception ignored) {
        }
    }

    private Intent buildCameraCaptureIntent(Uri outputUri, String facing) {
        Intent camIntent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
        camIntent.putExtra(MediaStore.EXTRA_OUTPUT, outputUri);
        camIntent.setClipData(ClipData.newRawUri("", outputUri));
        camIntent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_READ_URI_PERMISSION);
        if ("user".equalsIgnoreCase(facing)) {
            camIntent.putExtra("android.intent.extras.CAMERA_FACING", 1);
            camIntent.putExtra("android.intent.extra.USE_FRONT_CAMERA", true);
        } else {
            camIntent.putExtra("android.intent.extras.CAMERA_FACING", 0);
            camIntent.putExtra("android.intent.extra.USE_FRONT_CAMERA", false);
        }
        grantUriPermissionsForIntent(camIntent, outputUri);
        return camIntent;
    }

    private void startNativeCameraCapture(String facing, String callbackFn) {
        if (Build.VERSION.SDK_INT >= 23 && checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            pendingNativeFacing = facing != null ? facing : "environment";
            pendingNativeCallbackFn = callbackFn != null ? callbackFn : "";
            requestPermissions(new String[]{Manifest.permission.CAMERA}, REQ_CAMERA_NATIVE);
            return;
        }
        launchDirectCameraIntent(facing, callbackFn);
    }

    private void launchDirectCameraIntent(String facing, String callbackFn) {
        pendingNativeCallbackFn = callbackFn != null ? callbackFn : "";
        pendingNativePhotoFile = null;
        try {
            String fname = "gp_cam_" + System.currentTimeMillis() + ".jpg";
            File photoFile = PhotoContentProvider.getPhotoFile(this, fname);
            Uri photoUri = PhotoContentProvider.getContentUri(this, fname);
            pendingNativePhotoFile = photoFile;
            startActivityForResult(buildCameraCaptureIntent(photoUri, facing), REQ_NATIVE_CAMERA);
        } catch (Exception e) {
            deliverNativePhoto(pendingNativeCallbackFn, "");
            Toast.makeText(this, "Cannot open device camera", Toast.LENGTH_SHORT).show();
        }
    }

    private void deliverNativePhoto(String callbackFn, String dataUrl) {
        if (webView == null || callbackFn == null || callbackFn.isEmpty()) return;
        String safeFn = callbackFn.replaceAll("[^A-Za-z0-9_]", "");
        if (safeFn.isEmpty()) return;
        String js = "if(typeof window[" + JSONObject.quote(safeFn) + "]==='function'){window[" + JSONObject.quote(safeFn) + "](" + JSONObject.quote(dataUrl != null ? dataUrl : "") + ");}";
        runOnUiThread(() -> { if (webView != null) webView.evaluateJavascript(js, null); });
    }

    private String encodeFileOrBitmapToDataUrl(File file, Bitmap inlineBmp) {
        try {
            Bitmap bmp = null;
            if (file != null && file.exists() && file.length() > 0) {
                BitmapFactory.Options bounds = new BitmapFactory.Options();
                bounds.inJustDecodeBounds = true;
                BitmapFactory.decodeFile(file.getAbsolutePath(), bounds);
                int maxDim = Math.max(bounds.outWidth, bounds.outHeight);
                int sample = 1;
                while (maxDim / sample > 2048) sample *= 2;
                BitmapFactory.Options opts = new BitmapFactory.Options();
                opts.inSampleSize = sample;
                bmp = BitmapFactory.decodeFile(file.getAbsolutePath(), opts);
                if (bmp != null) {
                    try {
                        ExifInterface exif = new ExifInterface(file.getAbsolutePath());
                        int orient = exif.getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL);
                        int deg = orient == ExifInterface.ORIENTATION_ROTATE_90 ? 90 : (orient == ExifInterface.ORIENTATION_ROTATE_180 ? 180 : (orient == ExifInterface.ORIENTATION_ROTATE_270 ? 270 : 0));
                        if (deg != 0) {
                            Matrix m = new Matrix();
                            m.postRotate(deg);
                            Bitmap rotated = Bitmap.createBitmap(bmp, 0, 0, bmp.getWidth(), bmp.getHeight(), m, true);
                            if (rotated != bmp) { bmp.recycle(); bmp = rotated; }
                        }
                    } catch (Exception ignored) {
                    }
                }
            } else if (inlineBmp != null) {
                bmp = inlineBmp;
            }
            if (bmp == null) return "";
            int w = bmp.getWidth(), h = bmp.getHeight(), target = 1280;
            if (w > target || h > target) {
                int nw = w >= h ? target : Math.max(1, Math.round(w * (target / (float) h)));
                int nh = h > w ? target : Math.max(1, Math.round(h * (target / (float) w)));
                Bitmap scaled = Bitmap.createScaledBitmap(bmp, nw, nh, true);
                if (scaled != bmp) { bmp.recycle(); bmp = scaled; }
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            bmp.compress(Bitmap.CompressFormat.JPEG, 82, baos);
            bmp.recycle();
            return "data:image/jpeg;base64," + Base64.encodeToString(baos.toByteArray(), Base64.NO_WRAP);
        } catch (Exception e) {
            return "";
        } finally {
            if (file != null && file.exists()) try { file.delete(); } catch (Exception ignored) {}
        }
    }

    private void launchFileChooserWithCamera(WebChromeClient.FileChooserParams fileChooserParams) {
        pendingCameraPhotoUri = null;
        pendingCameraPhotoFile = null;
        try {
            Intent contentIntent = fileChooserParams != null ? fileChooserParams.createIntent() : new Intent(Intent.ACTION_GET_CONTENT).setType("image/*");
            if (fileChooserParams != null && fileChooserParams.getMode() == WebChromeClient.FileChooserParams.MODE_OPEN_MULTIPLE) {
                contentIntent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
            }
            List<Intent> extraIntents = new ArrayList<>();
            if (acceptsImageTypes(fileChooserParams) && (Build.VERSION.SDK_INT < 23 || checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)) {
                String fname = "gp_pick_" + System.currentTimeMillis() + ".jpg";
                pendingCameraPhotoFile = PhotoContentProvider.getPhotoFile(this, fname);
                pendingCameraPhotoUri = PhotoContentProvider.getContentUri(this, fname);
                extraIntents.add(buildCameraCaptureIntent(pendingCameraPhotoUri, "environment"));
            }
            Intent chooser = Intent.createChooser(contentIntent, "Camera or Select Photos");
            if (!extraIntents.isEmpty()) chooser.putExtra(Intent.EXTRA_INITIAL_INTENTS, extraIntents.toArray(new Intent[0]));
            startActivityForResult(chooser, REQ_FILE_CHOOSER);
        } catch (Exception e) {
            if (fileUploadCallback != null) { fileUploadCallback.onReceiveValue(null); fileUploadCallback = null; }
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQ_CAMERA_PERM && pendingPermissionRequest != null) {
            PermissionRequest req = pendingPermissionRequest;
            String[] grantRes = pendingGrantResources;
            pendingPermissionRequest = null;
            pendingGrantResources = null;
            boolean allOk = grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED;
            if (allOk) req.grant(grantRes != null ? grantRes : new String[]{PermissionRequest.RESOURCE_VIDEO_CAPTURE});
            else req.deny();
        } else if (requestCode == REQ_CAMERA_CHOOSER) {
            WebChromeClient.FileChooserParams cp = pendingChooserParams;
            pendingChooserParams = null;
            launchFileChooserWithCamera(cp);
        } else if (requestCode == REQ_CAMERA_NATIVE) {
            String cbFn = pendingNativeCallbackFn;
            String facing = pendingNativeFacing;
            pendingNativeCallbackFn = "";
            if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) launchDirectCameraIntent(facing, cbFn);
            else { deliverNativePhoto(cbFn, ""); Toast.makeText(this, "Allow Camera permission in App Settings.", Toast.LENGTH_LONG).show(); }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_NATIVE_CAMERA) {
            final String cbFn = pendingNativeCallbackFn;
            final File photoFile = pendingNativePhotoFile;
            pendingNativeCallbackFn = "";
            pendingNativePhotoFile = null;
            if (resultCode != RESULT_OK) {
                if (photoFile != null && photoFile.exists()) try { photoFile.delete(); } catch (Exception ignored) {}
                deliverNativePhoto(cbFn, "");
                return;
            }
            Bitmap thumb = (data != null && data.getExtras() != null && data.getExtras().get("data") instanceof Bitmap) ? (Bitmap) data.getExtras().get("data") : null;
            new Thread(() -> deliverNativePhoto(cbFn, encodeFileOrBitmapToDataUrl(photoFile, thumb)), "gp-cam-encode").start();
            return;
        }
        if (requestCode == REQ_FILE_CHOOSER && fileUploadCallback != null) {
            Uri[] result = null;
            if (resultCode == RESULT_OK) {
                if (data != null && data.getClipData() != null && data.getClipData().getItemCount() > 0) {
                    ClipData clip = data.getClipData();
                    List<Uri> uris = new ArrayList<>();
                    for (int i = 0; i < clip.getItemCount(); i++) { Uri u = clip.getItemAt(i).getUri(); if (u != null) uris.add(u); }
                    if (!uris.isEmpty()) result = uris.toArray(new Uri[0]);
                }
                if (result == null) result = WebChromeClient.FileChooserParams.parseResult(resultCode, data);
                if ((result == null || result.length == 0) && pendingCameraPhotoUri != null && pendingCameraPhotoFile != null && pendingCameraPhotoFile.exists() && pendingCameraPhotoFile.length() > 0) {
                    result = new Uri[]{pendingCameraPhotoUri};
                }
            }
            pendingCameraPhotoUri = null;
            pendingCameraPhotoFile = null;
            fileUploadCallback.onReceiveValue(result);
            fileUploadCallback = null;
        }
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) webView.goBack();
        else super.onBackPressed();
    }

    private final class ShreeBridge {
        @JavascriptInterface
        public void notify(String title, String body, String targetView, String targetId) {
            NotificationHelper.showAlert(MainActivity.this, title, body, targetView, targetId);
        }

        @JavascriptInterface
        public void openServerSettings() {
            runOnUiThread(() -> startActivity(new Intent(MainActivity.this, ServerSetupActivity.class)));
        }

        @JavascriptInterface
        public String getAppVersion() {
            return "1.0.0";
        }

        @JavascriptInterface
        public boolean hasNativeCamera() {
            return true;
        }

        @JavascriptInterface
        public void openCamera(String callbackFn) {
            runOnUiThread(() -> startNativeCameraCapture("environment", callbackFn));
        }

        @JavascriptInterface
        public void captureCameraPhoto(String facing, String callbackFn) {
            runOnUiThread(() -> startNativeCameraCapture(facing, callbackFn));
        }
    }
}
