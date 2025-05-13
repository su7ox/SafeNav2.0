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

    // 1. Run SSL check
    boolean sslSafe = sslCheckService.checkSSL(url);
    int sslScore = sslSafe ? 90 : 40;

    // 2. TEMP phishing and domain logic
    int phishingScore = 10; // dummy placeholder
    String domainReputation = "Good"; // dummy placeholder

    // 3. Compute combined risk score (you can adjust weights later)
    int riskScore = (sslSafe ? 20 : 80) + phishingScore;
    riskScore = Math.min(riskScore, 100); // cap it to 100

    // 4. Prepare response
    UrlResponse response = new UrlResponse();
    response.setSafe(riskScore < 50);
    response.setRiskScore(riskScore);
    response.setMessage(riskScore < 50 ? "URL is Safe" : "URL is Risky");
    response.setSslScore(sslScore);
    response.setPhishingScore(phishingScore);
    response.setDomainReputation(domainReputation);

    // 5. Verdict
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
