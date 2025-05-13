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
            // Normalize input
            if (!inputUrl.startsWith("https://")) {
                inputUrl = "https://" + inputUrl;
            }

            URI uri = new URI(inputUrl);
            URL url = uri.toURL();

            // Step 1: Temporarily trust all certs to fetch chain
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllManagers(), new SecureRandom());

            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.setHostnameVerifier((hostname, session) -> true);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.connect();

            Certificate[] certs = conn.getServerCertificates();
            conn.disconnect();

            // Step 2: Convert to X509Certificate[]
            List<X509Certificate> chainList = new ArrayList<>();
            for (Certificate cert : certs) {
                if (cert instanceof X509Certificate) {
                    chainList.add((X509Certificate) cert);
                }
            }

            if (chainList.isEmpty()) return false;

            // Step 3: Validate using DFS traversal
            return validateWithDFS(chainList);

        } catch (Exception e) {
            System.err.println("SSL Check Failed: " + e.getMessage());
            return false;
        }
    }

    // ---------------------------------
    // DFS-based cert chain validation
    // ---------------------------------
    private boolean validateWithDFS(List<X509Certificate> chain) {
        try {
            // Load default truststore
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);

            // Setup CertPathValidator
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            PKIXParameters params = new PKIXParameters(trustStore);
            params.setRevocationEnabled(false); // Skip CRL/OCSP for demo

            // DFS: try to build a valid path from chain
            Set<X509Certificate> visited = new HashSet<>();
            return dfsValidate(chain.get(0), chain, visited, certFactory, validator, params);

        } catch (Exception e) {
            System.err.println("DFS Validation Failed: " + e.getMessage());
            return false;
        }
    }

    private boolean dfsValidate(
        X509Certificate current,
        List<X509Certificate> fullChain,
        Set<X509Certificate> visited,
        CertificateFactory certFactory,
        CertPathValidator validator,
        PKIXParameters params
    ) {
        try {
            if (visited.contains(current)) return false;
            visited.add(current);

            // Build potential path from current cert
            List<X509Certificate> path = new ArrayList<>();
            path.add(current);
            CertPath certPath = certFactory.generateCertPath(path);
            validator.validate(certPath, params); // ✅ Trusted root
            return true;

        } catch (Exception ignored) {
            // Try DFS to find a trusted parent
            for (X509Certificate next : fullChain) {
                if (!visited.contains(next) &&
                    current.getIssuerX500Principal().equals(next.getSubjectX500Principal())) {
                    if (dfsValidate(next, fullChain, visited, certFactory, validator, params)) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    // ---------------------------------
    // Trust all manager (for fetching)
    // ---------------------------------
    private TrustManager[] trustAllManagers() {
        return new TrustManager[]{
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] xcs, String string) {}
                public void checkServerTrusted(X509Certificate[] xcs, String string) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }
        };
    }
}
