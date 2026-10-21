import sys

p = r"C:\Users\mohsen\.openclaw-autoclaw\workspace\terminus-secrets\android-app\app\src\main\java\com\terminus\secrets\MainActivity.java"
s = open(p, encoding="utf-8").read()

old_client = '''        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                if (progress != null) progress.setVisibility(View.GONE);
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                String host = Uri.parse(serverUrl).getHost();
                if (uri.getHost() != null && !uri.getHost().equalsIgnoreCase(host)) {
                    try {
                        startActivity(new Intent(Intent.ACTION_VIEW, uri));
                    } catch (ActivityNotFoundException ignored) {
                    }
                    return true;
                }
                return false;
            }

            @Override
            public void onReceivedSslError(WebView view, android.webkit.SslErrorHandler handler, SslError error) {
                String seen = fingerprintOf(error.getCertificate());
                if (seen != null && pin != null &&
                        seen.replace(":", "").equalsIgnoreCase(pin.replace(":", ""))) {
                    handler.proceed();
                } else {
                    handler.cancel();
                    Toast.makeText(MainActivity.this,
                            "Host certificate does not match the trusted pin.",
                            Toast.LENGTH_LONG).show();
                }
            }
        });
'''
new_client = '''        webView.setWebViewClient(new ChatWebViewClient(this));
'''
if old_client not in s:
    raise SystemExit("WebViewClient block not found")
s = s.replace(old_client, new_client)

old_trust = '''            final TrustManager[] trustAll = new TrustManager[]{
                    new X509TrustManager() {
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
            };
'''
new_trust = '''            final TrustManager[] trustAll = new TrustManager[]{new TrustAllManager()};
'''
if old_trust not in s:
    raise SystemExit("TrustManager block not found")
s = s.replace(old_trust, new_trust)

marker = '''    private static class HostInfo {
'''
nested = '''    /** Accepts any certificate only while probing /api/health, so the user can
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
'''
if marker not in s:
    raise SystemExit("HostInfo marker not found")
s = s.replace(marker, nested, 1)
open(p, "w", encoding="utf-8", newline="\n").write(s)
print("patched")
