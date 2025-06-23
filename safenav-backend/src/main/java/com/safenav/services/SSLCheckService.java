package com.safenav.services;

import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.net.URI;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SSLCheckService {
    
    private final Map<X509Certificate, Boolean> validationCache = new ConcurrentHashMap<>();
    private KeyStore trustStore;
    private CertPathValidator validator;
    private CertificateFactory certFactory;

    public SSLCheckService() {
        try {
            this.trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            String trustStorePath = System.getProperty("java.home") + "/lib/security/cacerts";
            trustStore.load(new FileInputStream(trustStorePath), "changeit".toCharArray());
            
            this.validator = CertPathValidator.getInstance("PKIX");
            this.certFactory = CertificateFactory.getInstance("X.509");
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize trust store", e);
        }
    }

    public boolean checkSSL(String inputUrl) {
        try {
            if (!inputUrl.startsWith("https://")) {
                inputUrl = "https://" + inputUrl;
            }

            URI uri = new URI(inputUrl);
            URL url = uri.toURL();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllManagers(), new SecureRandom());

            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.setHostnameVerifier((hostname, session) -> true);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.connect();

            List<X509Certificate> chain = new ArrayList<>();
            for (Certificate cert : conn.getServerCertificates()) {
                if (cert instanceof X509Certificate) {
                    chain.add((X509Certificate) cert);
                }
            }
            conn.disconnect();

            return !chain.isEmpty() && validateWithDFS(chain.get(0), chain);

        } catch (Exception e) {
            return false;
        }
    }

    public int calculateSSLScore(List<X509Certificate> chain) {
        if (chain.isEmpty()) return 0;
        
        int score = 100;
        X509Certificate leafCert = chain.get(0);
        
        if (isSelfSigned(leafCert)) score -= 40;
        if (isExpired(leafCert)) score -= 30;
        if (chain.size() < 3) score -= 20;
        
        return Math.max(0, score);
    }

    private boolean validateWithDFS(X509Certificate startCert, List<X509Certificate> fullChain) {
        Set<X509Certificate> visited = new HashSet<>();
        return dfsValidation(startCert, fullChain, visited);
    }

    private boolean dfsValidation(X509Certificate current, 
                                List<X509Certificate> chain,
                                Set<X509Certificate> visited) {
        if (validationCache.containsKey(current)) {
            return validationCache.get(current);
        }
        
        if (visited.contains(current)) {
            return false;
        }
        visited.add(current);

        try {
            
            List<X509Certificate> path = buildPath(current, chain);
            CertPath certPath = certFactory.generateCertPath(path);
            
            PKIXParameters params = new PKIXParameters(trustStore);
            params.setRevocationEnabled(false);
            
            validator.validate(certPath, params);
            validationCache.put(current, true);
            return true;
        } catch (CertPathValidatorException e) {
         
        } catch (Exception e) {
            return false;
        }


        for (X509Certificate issuer : findIssuers(current, chain)) {
            if (dfsValidation(issuer, chain, new HashSet<>(visited))) {
                validationCache.put(current, true);
                return true;
            }
        }

        validationCache.put(current, false);
        return false;
    }

    private List<X509Certificate> buildPath(X509Certificate start, List<X509Certificate> chain) {
        List<X509Certificate> path = new ArrayList<>();
        X509Certificate current = start;
        
        while (current != null) {
            path.add(current);
            current = findIssuer(current, chain);
        }
        return path;
    }

    private X509Certificate findIssuer(X509Certificate cert, List<X509Certificate> chain) {
        return chain.stream()
            .filter(c -> cert.getIssuerX500Principal().equals(c.getSubjectX500Principal()))
            .findFirst()
            .orElse(null);
    }

    private List<X509Certificate> findIssuers(X509Certificate cert, List<X509Certificate> chain) {
        return chain.stream()
            .filter(c -> cert.getIssuerX500Principal().equals(c.getSubjectX500Principal()))
            .toList();
    }

    private boolean isSelfSigned(X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isExpired(X509Certificate cert) {
        try {
            cert.checkValidity();
            return false;
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            return true;
        }
    }

    private TrustManager[] trustAllManagers() {
        return new TrustManager[]{
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }
        };
    }
}