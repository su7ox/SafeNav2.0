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

            // Temporarily trust all certs to fetch the chain
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, getTrustAllManagers(), new SecureRandom());

            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.setHostnameVerifier((hostname, session) -> true); // Bypass hostname check
            conn.setConnectTimeout(4000);
            conn.setReadTimeout(4000);
            conn.connect();

            Certificate[] certs = conn.getServerCertificates();
            conn.disconnect();

            if (certs.length == 0) return false;

            // Convert to X509Certificate array
            X509Certificate[] chain = Arrays.stream(certs)
                .filter(c -> c instanceof X509Certificate)
                .toArray(X509Certificate[]::new);

            // Load system truststore
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null); // Loads default cacerts

            // DFS Validation
            return validateWithDFS(chain[0], chain, trustStore, new HashSet<>());

        } catch (Exception e) {
            System.err.println("SSL Check Failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * DFS-based validation with truststore checking.
     */
    private boolean validateWithDFS(
        X509Certificate current,
        X509Certificate[] chain,
        KeyStore trustStore,
        Set<X509Certificate> visited
    ) throws Exception {
        // Base case: Found a trusted root CA
        if (isTrustedRoot(current, trustStore)) {
            return true;
        }

        // Prevent cycles
        if (visited.contains(current)) return false;
        visited.add(current);

        // Recursive case: Check all possible issuers
        for (X509Certificate cert : chain) {
            if (isIssuer(current, cert)) {
                if (validateWithDFS(cert, chain, trustStore, visited)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Checks if a certificate is a trusted root CA.
     */
    private boolean isTrustedRoot(X509Certificate cert, KeyStore trustStore) throws Exception {
        // Check if the cert is self-signed
        if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
            return false;
        }

        // Check if the root CA is in the truststore
        return trustStore.getCertificateAlias(cert) != null;
    }

    /**
     * Checks if 'potentialIssuer' issued 'child'.
     */
    private boolean isIssuer(X509Certificate child, X509Certificate potentialIssuer) {
        return child.getIssuerX500Principal().equals(potentialIssuer.getSubjectX500Principal());
    }

    /**
     * TEMPORARY: Trust all certificates (for fetching only).
     */
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