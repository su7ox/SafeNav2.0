package com.safenav.services;

import org.springframework.core.io.ClassPathResource;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import javax.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;

@Service
public class DomainCheckService {

    private static final String DOMAIN_GRAPH_URL = "https://safenav-data.com/domain-graph.csv";
    private static final String BLACKLIST_URL = "https://safenav-data.com/malicious-domains.txt";
    
    private Map<String, List<String>> domainGraph = new HashMap<>();
    private Set<String> blacklist = new HashSet<>();

    @PostConstruct
    @Scheduled(fixedRate = 3600000) 
    public void init() {
        loadDomainGraph();
        loadBlacklist();
    }

    private void loadDomainGraph() {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new ClassPathResource("domain-graph.csv").getInputStream()))) {
            
            domainGraph.clear();
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length > 1) {
                    String root = parts[0].trim().toLowerCase();
                    List<String> subdomains = new ArrayList<>();
                    for (int i = 1; i < parts.length; i++) {
                        subdomains.add(parts[i].trim().toLowerCase());
                    }
                    domainGraph.put(root, subdomains);
                }
            }
        } catch (Exception e) {
            System.err.println("Error loading domain graph: " + e.getMessage());
        }
    }

    private void loadBlacklist() {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new ClassPathResource("malicious-domains.txt").getInputStream()))) {
            
            blacklist.clear();
            String line;
            while ((line = reader.readLine()) != null) {
                String domain = line.trim().toLowerCase();
                if (!domain.isEmpty()) {
                    blacklist.add(domain);
                }
            }
        } catch (Exception e) {
            System.err.println("Error loading blacklist: " + e.getMessage());
        }
    }

    public String checkDomainReputation(String domain) {
        Set<String> visited = new HashSet<>();
        LinkedList<String> queue = new LinkedList<>();
        queue.add(domain.toLowerCase());
        int maliciousCount = 0;

        while (!queue.isEmpty()) {
            String current = queue.poll();
            if (blacklist.contains(current)) maliciousCount++;
            

            domainGraph.getOrDefault(current, Collections.emptyList())
                      .stream()
                      .filter(neighbor -> !visited.contains(neighbor))
                      .forEach(neighbor -> {
                          visited.add(neighbor);
                          queue.add(neighbor);
                      });
        }

        return calculateReputation(maliciousCount);
    }

    private String calculateReputation(int count) {
        return switch (count) {
            case 0 -> "Excellent (0 malicious associations)";
            case 1 -> "Good (1 suspicious association)";
            case 2 -> "Fair (2 risk associations)";
            default -> "Poor (" + count + " malicious associations)";
        };
    }
}