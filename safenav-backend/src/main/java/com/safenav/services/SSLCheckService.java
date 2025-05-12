package com.safenav.services;

import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.net.URI;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.*;
import java.util.*;

@Service
public class SSLCheckService {

    public boolean checkSSL(String inputUrl) {
        try {
            if (!inputUrl.startsWith("https://")) {
                inputUrl = "https://" + inputUrl;
            }

            URI uri = new URI(inputUrl);
            URL url = uri.toURL();

            // Step 1: Fetch certs (trust all temporarily)
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, getTrustAllManagers(), new SecureRandom());

            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.setHostnameVerifier((hostname, session) -> true);
            conn.setConnectTimeout(4000);
            conn.setReadTimeout(4000);
            conn.connect();

            Certificate[] certs = conn.getServerCertificates();
            conn.disconnect();

            if (certs.length == 0) return false;

            // Step 2: Convert to X509 chain
            X509Certificate[] chain = Arrays.stream(certs)
                .filter(c -> c instanceof X509Certificate)
                .toArray(X509Certificate[]::new);

            // Step 3: DFS traversal
            KeyStore trustStore = loadSystemTrustStore();
            X509Certificate start = chain[0];
            Set<X509Certificate> visited = new HashSet<>();

            return dfsCheck(start, chain, trustStore, visited);

        } catch (Exception e) {
            System.err.println("SSL Check Failed: " + e.getMessage());
            return false;
        }
    }

    private boolean dfsCheck(
        X509Certificate current,
        X509Certificate[] chain,
        KeyStore trustStore,
        Set<X509Certificate> visited
    ) throws Exception {
        if (visited.contains(current)) return false;
        visited.add(current);

        // ✅ Base case: trusted root cert
        if (isTrustedRoot(current, trustStore)) {
            return true;
        }

        // 🔁 DFS: find issuer in chain
        for (X509Certificate cert : chain) {
            if (isIssuer(current, cert)) {
                if (dfsCheck(cert, chain, trustStore, visited)) return true;
            }
        }

        return false;
    }

    private boolean isIssuer(X509Certificate child, X509Certificate parent) {
        return child.getIssuerX500Principal().equals(parent.getSubjectX500Principal());
    }

    private boolean isTrustedRoot(X509Certificate cert, KeyStore trustStore) throws Exception {
        if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) return false;

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                try {
                    ((X509TrustManager) tm).checkServerTrusted(new X509Certificate[]{cert}, "RSA");
                    return true;
                } catch (CertificateException e) {
                    return false;
                }
            }
        }
        return false;
    }

    private KeyStore loadSystemTrustStore() throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null); // Loads default system truststore (cacerts)
        return trustStore;
    }

    private TrustManager[] getTrustAllManagers() {
        return new TrustManager[] {
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }
        };
    }
}
