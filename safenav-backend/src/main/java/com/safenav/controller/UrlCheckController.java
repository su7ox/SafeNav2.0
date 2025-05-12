package com.safenav.controller;

import com.safenav.model.UrlRequest;
import com.safenav.model.UrlResponse;
import com.safenav.services.SSLCheckService;
import com.safenav.services.RiskCalculatorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*") // Allows frontend to access
public class UrlCheckController {

    @Autowired
    private SSLCheckService sslCheckService;

    @Autowired
    private RiskCalculatorService riskCalculatorService;

    @PostMapping("/check")
    public UrlResponse checkUrl(@RequestBody UrlRequest request) {
        String url = request.getUrl();

        boolean sslSafe = sslCheckService.checkSSL(url);
        int riskScore = riskCalculatorService.calculateRisk(sslSafe);

        UrlResponse response = new UrlResponse();
        response.setSafe(riskScore < 50);
        response.setRiskScore(riskScore);
        response.setMessage(riskScore < 50 ? "URL is Safe" : "URL is Risky");

        response.setSslScore(sslSafe ? 90 : 40); // Example logic
        response.setPhishingScore(riskScore); // Example: later can improve
        response.setDomainReputation(sslSafe ? "Good" : "Bad");

        if (riskScore < 30) {
            response.setFinalVerdict("Safe");
        } else if (riskScore < 60) {
            response.setFinalVerdict("Suspicious");
        } else {
            response.setFinalVerdict("Dangerous");
        }
        

        return response;
    }
}
