package com.terminus.secrets;

import android.Manifest;
import android.app.Activity;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Bundle;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.util.Base64;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.net.http.SslCertificate;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebChromeClient;
import android.webkit.PermissionRequest;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Terminus Secrets for Android.
 *
 * Native shell + the shared encrypted web client.  The shell performs
 * trust-on-first-use certificate pinning: the user compares the SHA-256
 * fingerprint shown here with the one printed by the host, and every later
 * TLS connection must match that pin.
 */
public class MainActivity extends Activity {

    private static final String PREFS = "terminus";
    private static final String PREF_URL = "server_url";
    private static final String PREF_PIN = "pin";
    private static final String PREF_NAME = "server_name";
    private static final String NOTIFICATION_CHANNEL = "terminus_messages";
    private static final int NOTIFICATION_PERMISSION_REQUEST = 4701;

    private static final int BG = Color.parseColor("#06090E");
    private static final int PANEL = Color.parseColor("#0C121A");
    private static final int LINE = Color.parseColor("#1C2735");
    private static final int TEXT = Color.parseColor("#E8EEF7");
    private static final int MUTED = Color.parseColor("#8395AA");
    private static final int FAINT = Color.parseColor("#5A6B7F");
    private static final int ACCENT = Color.parseColor("#3EE0C5");
    private static final int DANGER = Color.parseColor("#FF7185");

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());

    private SharedPreferences prefs;
    private WebView webView;
    private ProgressBar progress;
    private String serverUrl;
    private String pin;
    private static final int MEDIA_PERMISSION_REQUEST = 4702;
    private PermissionRequest pendingMediaRequest;
    private String[] pendingMediaResources = new String[0];

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);

        createNotificationChannel();
        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        serverUrl = prefs.getString(PREF_URL, "");
        pin = prefs.getString(PREF_PIN, "");

        if (serverUrl.isEmpty() || pin.isEmpty()) {
            showSetup(null);
        } else {
            showWeb();
        }
    }

    /* ------------------------------------------------------------------ */
    /* setup screen                                                        */
    /* ------------------------------------------------------------------ */
    private void showSetup(String error) {
        webView = null;

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BG);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(26), dp(38), dp(26), dp(32));
        scroll.addView(root);

        LinearLayout brand = new LinearLayout(this);
        brand.setOrientation(LinearLayout.HORIZONTAL);
        brand.setGravity(Gravity.CENTER_VERTICAL);
        root.addView(brand);

        TextView mark = new TextView(this);
        mark.setText("◇");
        mark.setTextColor(ACCENT);
        mark.setTextSize(30);
        brand.addView(mark);

        LinearLayout brandText = new LinearLayout(this);
        brandText.setOrientation(LinearLayout.VERTICAL);
        brandText.setPadding(dp(10), 0, 0, 0);
        TextView name = new TextView(this);
        name.setText("TERMINUS");
        name.setTextColor(TEXT);
        name.setTextSize(14);
        name.setLetterSpacing(0.28f);
        name.setTypeface(Typeface.DEFAULT_BOLD);
        TextView sub = new TextView(this);
        sub.setText("SECRETS");
        sub.setTextColor(ACCENT);
        sub.setTextSize(9);
        sub.setLetterSpacing(0.4f);
        sub.setTypeface(Typeface.MONOSPACE);
        brandText.addView(name);
        brandText.addView(sub);
        brand.addView(brandText);

        TextView title = new TextView(this);
        title.setText("Connect to your host.");
        title.setTextColor(TEXT);
        title.setTextSize(32);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setPadding(0, dp(38), 0, dp(10));
        root.addView(title);

        TextView lede = new TextView(this);
        lede.setText("Enter the address of the laptop running host.py. "
                + "You will verify its certificate fingerprint once; this device remembers only that identity.");
        lede.setTextColor(MUTED);
        lede.setTextSize(14);
        lede.setLineSpacing(dp(3), 1f);
        root.addView(lede);

        TextView label = new TextView(this);
        label.setText("HOST ADDRESS");
        label.setTextColor(FAINT);
        label.setTextSize(10);
        label.setLetterSpacing(0.18f);
        label.setTypeface(Typeface.MONOSPACE);
        label.setPadding(0, dp(30), 0, dp(7));
        root.addView(label);

        EditText input = new EditText(this);
        input.setText(prefs.getString(PREF_URL, "https://127.0.0.1:8443"));
        input.setTextColor(TEXT);
        input.setTextSize(14);
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        input.setPadding(dp(14), dp(13), dp(14), dp(13));
        input.setBackground(rounded(0xFF080E15, LINE, 12));
        root.addView(input, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        Button connect = new Button(this);
        connect.setText("Test & trust host");
        connect.setAllCaps(false);
        connect.setTextColor(Color.parseColor("#04211D"));
        connect.setTextSize(15);
        connect.setTypeface(Typeface.DEFAULT_BOLD);
        connect.setBackground(rounded(ACCENT, ACCENT, 12));
        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(50));
        buttonParams.topMargin = dp(18);
        root.addView(connect, buttonParams);

        TextView status = new TextView(this);
        status.setText(error == null ? "" : error);
        status.setTextColor(error == null ? FAINT : DANGER);
        status.setTextSize(12);
        status.setPadding(0, dp(14), 0, 0);
        status.setLineSpacing(dp(2), 1f);
        root.addView(status);

        TextView hint = new TextView(this);
        hint.setText("For direct IPv6 access without Tailscale, enter https://[your-global-ipv6]:8443 "
                + "(keep the square brackets). The host prints its fingerprint and pairing code; "
                + "you will enter the pairing code and vault passphrase next.");
        hint.setTextColor(FAINT);
        hint.setTextSize(11);
        hint.setLineSpacing(dp(3), 1f);
        hint.setPadding(0, dp(28), 0, 0);
        root.addView(hint);

        connect.setOnClickListener(v -> {
            String url = input.getText().toString().trim();
            while (url.endsWith("/")) url = url.substring(0, url.length() - 1);
            if (!url.startsWith("https://")) {
                status.setTextColor(DANGER);
                status.setText("Use the https:// address printed by the host.");
                return;
            }
            connect.setEnabled(false);
            status.setTextColor(FAINT);
            status.setText("Contacting host…");
            final String target = url;
            executor.execute(() -> {
                try {
                    HostInfo info = probe(target);
                    main.post(() -> {
                        connect.setEnabled(true);
                        status.setText("Host reached. Verify the fingerprint.");
                        showTrustDialog(info);
                    });
                } catch (Exception ex) {
                    main.post(() -> {
                        connect.setEnabled(true);
                        status.setTextColor(DANGER);
                        status.setText(ex.getMessage() == null ? "Connection failed." : ex.getMessage());
                    });
                }
            });
        });

        setContentView(scroll);
    }

    private void showTrustDialog(HostInfo info) {
        String pretty = prettyFingerprint(info.fingerprint);
        String message = info.serverName + "  ·  v" + info.version + "\n\n"
                + "Certificate SHA-256:\n" + pretty + "\n\n"
                + "Compare this with the fingerprint printed in the host window. "
                + "If it differs, do not continue.";

        new AlertDialog.Builder(this)
                .setTitle("Trust this host?")
                .setMessage(message)
                .setPositiveButton("Trust & open", (dialog, which) -> {
                    prefs.edit()
                            .putString(PREF_URL, info.url)
                            .putString(PREF_PIN, info.fingerprint)
                            .putString(PREF_NAME, info.serverName)
                            .apply();
                    serverUrl = info.url;
                    pin = info.fingerprint;
                    showWeb();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    /* ------------------------------------------------------------------ */
    /* web client                                                          */
    /* ------------------------------------------------------------------ */
    private void showWeb() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        root.setFitsSystemWindows(true);

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(16), 0, dp(10), 0);
        bar.setBackgroundColor(BG);

        TextView title = new TextView(this);
        title.setText(prefs.getString(PREF_NAME, "Terminus Secrets"));
        title.setTextColor(TEXT);
        title.setTextSize(15);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setSingleLine(true);
        bar.addView(title, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView serverButton = new TextView(this);
        serverButton.setText("SERVER");
        serverButton.setTextColor(ACCENT);
        serverButton.setTextSize(10);
        serverButton.setLetterSpacing(0.14f);
        serverButton.setTypeface(Typeface.MONOSPACE);
        serverButton.setPadding(dp(12), dp(12), dp(12), dp(12));
        serverButton.setOnClickListener(v -> confirmChangeServer());
        bar.addView(serverButton);

        root.addView(bar, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(54)));

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setIndeterminate(true);
        progress.setProgressTintList(ColorStateList.valueOf(ACCENT));
        progress.setBackgroundColor(PANEL);
        root.addView(progress, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(2)));

        webView = new WebView(this);
        webView.setBackgroundColor(BG);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setSupportZoom(false);
        settings.setBuiltInZoomControls(false);
        settings.setMediaPlaybackRequiresUserGesture(true);
        settings.setCacheMode(WebSettings.LOAD_DEFAULT);
        settings.setUserAgentString(settings.getUserAgentString() + " TerminusAndroid/1.0");

        webView.setWebViewClient(new ChatWebViewClient(this));
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onPermissionRequest(PermissionRequest request) {
                runOnUiThread(() -> {
                    java.util.ArrayList<String> approvedResources = new java.util.ArrayList<>();
                    java.util.ArrayList<String> neededPermissions = new java.util.ArrayList<>();
                    for (String resource : request.getResources()) {
                        if (PermissionRequest.RESOURCE_AUDIO_CAPTURE.equals(resource)) {
                            approvedResources.add(resource);
                            if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
                                neededPermissions.add(Manifest.permission.RECORD_AUDIO);
                            }
                        } else if (PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(resource)) {
                            approvedResources.add(resource);
                            if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                                neededPermissions.add(Manifest.permission.CAMERA);
                            }
                        }
                    }
                    if (approvedResources.isEmpty()) {
                        request.deny();
                        return;
                    }
                    pendingMediaResources = approvedResources.toArray(new String[0]);
                    if (!neededPermissions.isEmpty()) {
                        pendingMediaRequest = request;
                        requestPermissions(neededPermissions.toArray(new String[0]), MEDIA_PERMISSION_REQUEST);
                    } else {
                        request.grant(pendingMediaResources);
                    }
                });
            }

            @Override
            public void onPermissionRequestCanceled(PermissionRequest request) {
                if (pendingMediaRequest == request) {
                    pendingMediaRequest = null;
                    pendingMediaResources = new String[0];
                }
            }
        });
        webView.addJavascriptInterface(new NativeNotifications(), "TerminusNative");

        root.addView(webView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);
        webView.loadUrl(serverUrl + "/app/");
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != MEDIA_PERMISSION_REQUEST) return;
        PermissionRequest request = pendingMediaRequest;
        pendingMediaRequest = null;
        if (request == null) return;
        boolean granted = grantResults.length > 0;
        for (int result : grantResults) granted &= result == PackageManager.PERMISSION_GRANTED;
        if (granted) request.grant(pendingMediaResources);
        else request.deny();
        pendingMediaResources = new String[0];
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    NOTIFICATION_CHANNEL, "New messages", NotificationManager.IMPORTANCE_DEFAULT);
            channel.setDescription("Alerts when Terminus Secrets receives a new message.");
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) manager.createNotificationChannel(channel);
        }
    }

    private final class NativeNotifications {
        @JavascriptInterface
        public void notifyMessage(String roomName) {
            final String safeRoom = (roomName == null || roomName.trim().isEmpty())
                    ? "a channel" : roomName.trim().substring(0, Math.min(48, roomName.trim().length()));
            runOnUiThread(() -> {
                if (Build.VERSION.SDK_INT >= 33
                        && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                        != PackageManager.PERMISSION_GRANTED) {
                    requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},
                            NOTIFICATION_PERMISSION_REQUEST);
                    return;
                }
                Intent intent = new Intent(MainActivity.this, MainActivity.class);
                intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
                PendingIntent pending = PendingIntent.getActivity(
                        MainActivity.this, 0, intent,
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
                Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                        ? new Notification.Builder(MainActivity.this, NOTIFICATION_CHANNEL)
                        : new Notification.Builder(MainActivity.this);
                builder.setSmallIcon(android.R.drawable.ic_dialog_info)
                        .setContentTitle("Terminus Secrets")
                        .setContentText("New message in #" + safeRoom)
                        .setContentIntent(pending)
                        .setAutoCancel(true)
                        .setCategory(Notification.CATEGORY_MESSAGE);
                NotificationManager manager = (NotificationManager)
                        getSystemService(NOTIFICATION_SERVICE);
                if (manager != null) manager.notify((safeRoom.hashCode() & 0x7fffffff), builder.build());
            });
        }
    }

    private void confirmChangeServer() {
        new AlertDialog.Builder(this)
                .setTitle("Change host?")
                .setMessage("This forgets the saved address and certificate pin. "
                        + "Chat history stays on the host.")
                .setPositiveButton("Change", (dialog, which) -> {
                    prefs.edit().clear().apply();
                    serverUrl = "";
                    pin = "";
                    showSetup(null);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
            return;
        }
        super.onBackPressed();
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        if (webView != null) {
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }

    /* ------------------------------------------------------------------ */
    /* networking / crypto helpers                                         */
    /* ------------------------------------------------------------------ */
    private HostInfo probe(String url) throws Exception {
        HttpsURLConnection connection = null;
        try {
            URL health = new URL(url + "/api/health");
            connection = (HttpsURLConnection) health.openConnection();
            connection.setConnectTimeout(9000);
            connection.setReadTimeout(9000);
            connection.setRequestProperty("Accept", "application/json");

            final TrustManager[] trustAll = new TrustManager[]{new TrustAllManager()};
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustAll, new java.security.SecureRandom());
            connection.setSSLSocketFactory(context.getSocketFactory());
            connection.setHostnameVerifier((hostname, session) -> true);

            int code = connection.getResponseCode();
            if (code != 200) {
                throw new IllegalStateException("Host answered HTTP " + code + ".");
            }
            StringBuilder text = new StringBuilder();
            try (InputStream stream = connection.getInputStream();
                 BufferedReader reader = new BufferedReader(
                         new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) text.append(line);
            }
            JSONObject json = new JSONObject(text.toString());
            if (!"terminus-secrets".equals(json.optString("app"))) {
                throw new IllegalStateException("That address is not a Terminus Secrets host.");
            }

            Certificate[] certificates = connection.getServerCertificates();
            if (certificates.length == 0) {
                throw new IllegalStateException("Host did not present a certificate.");
            }
            String fingerprint = sha256(certificates[0].getEncoded());

            HostInfo info = new HostInfo();
            info.url = url;
            info.fingerprint = fingerprint;
            info.serverName = json.optString("server_name", "Terminus host");
            info.version = json.optString("version", "?");
            return info;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private String fingerprintOf(SslCertificate certificate) {
        if (certificate == null) return null;
        Bundle bundle = SslCertificate.saveState(certificate);
        byte[] bytes = bundle == null ? null : bundle.getByteArray("x509-certificate");
        if (bytes == null) return null;
        try {
            return sha256(bytes);
        } catch (Exception ex) {
            return null;
        }
    }

    private static String sha256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        StringBuilder hex = new StringBuilder();
        for (byte b : hash) hex.append(String.format(Locale.US, "%02x", b));
        return hex.toString();
    }

    private static String prettyFingerprint(String raw) {
        String clean = raw.replace(":", "").toUpperCase(Locale.US);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < clean.length(); i += 2) {
            if (i > 0) out.append(':');
            out.append(clean, i, Math.min(i + 2, clean.length()));
        }
        return out.toString();
    }

    private GradientDrawable rounded(int fill, int stroke, int radiusDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(radiusDp));
        if (stroke != 0) drawable.setStroke(dp(1), stroke);
        return drawable;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    /** Accepts any certificate only while probing /api/health, so the user can
     *  inspect and pin the fingerprint before any secret is sent. */
    private static class TrustAllManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    private static class ChatWebViewClient extends WebViewClient {
        private final MainActivity activity;

        ChatWebViewClient(MainActivity activity) {
            this.activity = activity;
        }

        @Override
        public void onPageFinished(WebView view, String url) {
            if (activity.progress != null) activity.progress.setVisibility(View.GONE);
        }

        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            Uri uri = request.getUrl();
            String host = Uri.parse(activity.serverUrl).getHost();
            if (uri.getHost() != null && !uri.getHost().equalsIgnoreCase(host)) {
                try {
                    activity.startActivity(new Intent(Intent.ACTION_VIEW, uri));
                } catch (ActivityNotFoundException ignored) {
                }
                return true;
            }
            return false;
        }

        @Override
        public void onReceivedSslError(WebView view, android.webkit.SslErrorHandler handler, SslError error) {
            String seen = activity.fingerprintOf(error.getCertificate());
            if (seen != null && activity.pin != null &&
                    seen.replace(":", "").equalsIgnoreCase(activity.pin.replace(":", ""))) {
                handler.proceed();
            } else {
                handler.cancel();
                Toast.makeText(activity,
                        "Host certificate does not match the trusted pin.",
                        Toast.LENGTH_LONG).show();
            }
        }
    }

    private static class HostInfo {
        String url;
        String fingerprint;
        String serverName;
        String version;
    }
}

