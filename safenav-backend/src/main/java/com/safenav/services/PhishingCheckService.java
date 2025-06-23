package com.safenav.services;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.*;

@Service
public class PhishingCheckService {

    private static final int MAX_CACHE_SIZE = 10_000;
    private Set<String> maliciousDomains;
    private Set<String> safeList;
    private Map<String, Integer> distanceCache;

    @PostConstruct
    public void init() {
        maliciousDomains = new HashSet<>(1024);
        safeList = new HashSet<>(128);
        distanceCache = new LinkedHashMap<>(MAX_CACHE_SIZE, 0.75f, true) {
            protected boolean removeEldestEntry(Map.Entry eldest) {
                return size() > MAX_CACHE_SIZE;
            }
        };

        loadMaliciousDomains();
        loadSafeList();
    }

    private void loadMaliciousDomains() {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(
                        new ClassPathResource("malicious_domains.txt").getInputStream()))) {

            String line;
            while ((line = reader.readLine()) != null) {
                String raw = line.trim().toLowerCase();
                if (!raw.isEmpty() && !raw.startsWith("#")) {
                    String domain = extractDomain(raw);
                    if (!domain.isEmpty()) {
                        maliciousDomains.add(domain);
                    }
                }
            }

            System.out.println("Loaded " + maliciousDomains.size() + " malicious domains");

        } catch (Exception e) {
            System.err.println("Error loading malicious domains: " + e.getMessage());
            loadFallbackDomains();
        }
    }

    private void loadFallbackDomains() {
        maliciousDomains.addAll(Arrays.asList(
                "faceb00k.com", "g00gle-login.net", "amaz0n-payments.ru",
                "paypa1-login.cn", "apple1d-login.xyz", "m1crosoft-auth.net",
                "netfl1x-premium.cc", "bank0famerica.ru", "wellsfarg0-0nline.com"
        ));
    }

    private void loadSafeList() {
        safeList.addAll(Arrays.asList(
                "google.com", "open.spotify.com", "microsoft.com", "youtube.com",
                "github.com", "amazon.com", "netflix.com", "apple.com"
        ));
    }

    public int calculatePhishingScore(String url) {
        String domain = extractDomain(url);
        if (domain == null || domain.isEmpty()) return 100;

        if (safeList.contains(domain)) return 0; 
        if (maliciousDomains.contains(domain)) return 100;

        int minDistance = maliciousDomains.parallelStream()
                .mapToInt(malicious -> calculateLevenshtein(domain, malicious))
                .min()
                .orElse(100);

        return convertDistanceToScore(minDistance);
    }

    private int convertDistanceToScore(int distance) {
        return Math.max(0, 100 - (distance * 10));
    }

    private int calculateLevenshtein(String a, String b) {
        if (a.length() > b.length()) {
            String temp = a;
            a = b;
            b = temp;
        }

        String key = a + "|" + b;
        Integer cached = distanceCache.get(key);
        if (cached != null) return cached;

        int[] dp = new int[a.length() + 1];
        for (int i = 0; i <= a.length(); i++) dp[i] = i;

        for (int j = 1; j <= b.length(); j++) {
            int prev = dp[0];
            dp[0] = j;

            for (int i = 1; i <= a.length(); i++) {
                int cost = (a.charAt(i - 1) == b.charAt(j - 1)) ? 0 : 1;
                int temp = dp[i];
                dp[i] = Math.min(
                        Math.min(dp[i - 1] + 1, dp[i] + 1),
                        prev + cost
                );
                prev = temp;
            }
        }

        distanceCache.put(key, dp[a.length()]);
        return dp[a.length()];
    }

    private String extractDomain(String input) {
        try {
            URI uri = input.contains("://") ? new URI(input) : new URI("https://" + input);
            String domain = uri.getHost();
            if (domain == null) return "";
            return domain.toLowerCase().replaceFirst("^www\\.", "");
        } catch (Exception e) {
            return "";
        }
    }
}
