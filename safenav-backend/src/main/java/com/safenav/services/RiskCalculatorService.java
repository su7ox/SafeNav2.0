package com.safenav.services;

import org.springframework.stereotype.Service;

@Service
public class RiskCalculatorService {

    public int calculateRisk(boolean sslSafe) {
        // 🛠 Dummy Logic:
        // If SSL is safe → 20 risk points
        // If SSL not safe → 80 risk points
        return sslSafe ? 20 : 80;
    }
}
