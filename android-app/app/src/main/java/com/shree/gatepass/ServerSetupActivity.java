package com.shree.gatepass;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Toast;

public class ServerSetupActivity extends Activity {
    private EditText urlInput;
    private CheckBox bgAlertsCheck;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_setup);

        urlInput = findViewById(R.id.serverUrlInput);
        bgAlertsCheck = findViewById(R.id.bgAlertsCheck);
        Button connectBtn = findViewById(R.id.connectServerBtn);

        String saved = CertPinStore.getServerUrl(this);
        urlInput.setText(!saved.isEmpty() ? saved : "https://192.168.130.31:8859");
        bgAlertsCheck.setChecked(CertPinStore.isBgAlertsEnabled(this));
        connectBtn.setOnClickListener(v -> saveAndConnect());
    }

    private void saveAndConnect() {
        String raw = urlInput.getText() == null ? "" : urlInput.getText().toString().trim();
        if (raw.isEmpty()) {
            Toast.makeText(this, "Enter server URL", Toast.LENGTH_SHORT).show();
            return;
        }
        while (raw.endsWith("/")) {
            raw = raw.substring(0, raw.length() - 1);
        }
        if (!raw.startsWith("http://") && !raw.startsWith("https://")) {
            raw = (raw.contains(":8858") || raw.contains(":80")) ? ("http://" + raw) : ("https://" + raw);
        } else if (raw.startsWith("https://") && raw.matches("^https://[^/]+:8858(/.*)?$")) {
            raw = "http://" + raw.substring(8);
        } else if (raw.startsWith("http://") && raw.matches("^http://[^/]+:8859(/.*)?$")) {
            raw = "https://" + raw.substring(7);
        }
        Uri uri = Uri.parse(raw);
        if (uri == null || uri.getHost() == null || uri.getHost().isEmpty()) {
            Toast.makeText(this, "Enter a valid GatePass server URL", Toast.LENGTH_SHORT).show();
            return;
        }
        CertPinStore.setServerUrl(this, raw);
        CertPinStore.setBgAlertsEnabled(this, bgAlertsCheck.isChecked());

        Intent i = new Intent(this, MainActivity.class);
        i.putExtra("reload_url", true);
        i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(i);
        finish();
    }
}
