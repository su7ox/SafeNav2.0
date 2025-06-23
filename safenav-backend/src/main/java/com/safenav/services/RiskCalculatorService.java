package com.safenav.services;

import org.springframework.stereotype.Service;
import java.util.PriorityQueue;

@Service
public class RiskCalculatorService {

    public int calculateRisk(boolean sslValid, int phishingScore, String domainReputation) {
        PriorityQueue<Integer> riskQueue = new PriorityQueue<>((a, b) -> b - a);
        
        
        riskQueue.add(sslValid ? 0 : 60); // Highest priority
        riskQueue.add(phishingScore * 2); // Medium priority
        riskQueue.add(getDomainScore(domainReputation)); // Lowest priority

        int total = 0;
        while (!riskQueue.isEmpty() && total < 100) {
            total += riskQueue.poll();
            if (total > 100) return 100;
        }
        return total;
    }

    private int getDomainScore(String reputation) {
        return switch (reputation) {
            case "Poor" -> 40;
            case "Fair" -> 20;
            case "Good" -> 10;
            default -> 0;
        };
    }
}
