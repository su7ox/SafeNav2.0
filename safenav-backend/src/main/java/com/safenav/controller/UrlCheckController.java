package com.safenav.controller;

import com.safenav.model.UrlRequest;
import com.safenav.model.UrlResponse;
import com.safenav.services.SSLCheckService;
import com.safenav.services.RiskCalculatorService;
import com.safenav.services.PhishingCheckService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class UrlCheckController {

    @Autowired
    private SSLCheckService sslCheckService;

    @Autowired
    private RiskCalculatorService riskCalculatorService;

    @Autowired
    private PhishingCheckService phishingCheckService;

    @PostMapping("/check")
    public UrlResponse checkUrl(@RequestBody UrlRequest request) {
        String url = request.getUrl();

        // URL existence check
        if (!urlExists(url)) {
            UrlResponse errorResponse = new UrlResponse();
            errorResponse.setSafe(false);
            errorResponse.setRiskScore(100);
            errorResponse.setMessage("URL does not exist or is unreachable");
            errorResponse.setSslScore(0);
            errorResponse.setPhishingScore(100);
            errorResponse.setDomainReputation("Unknown");
            errorResponse.setFinalVerdict("Invalid URL");
            return errorResponse;
        }

        // SSL Check
        boolean sslSafe = sslCheckService.checkSSL(url);
        int sslScore = sslSafe ? 90 : 40;

        // Phishing Score
        int phishingScore = phishingCheckService.calculatePhishingScore(url);

        // Domain Reputation
        String domainReputation = phishingScore >= 70 ? "Bad" : "Good";

        // Final Risk Score
        int riskScore = (int) Math.round((sslScore * 0.4) + (phishingScore * 0.6));

        // Response
        UrlResponse response = new UrlResponse();
        response.setSafe(riskScore < 50);
        response.setRiskScore(riskScore);
        response.setMessage(riskScore < 50 ? "URL is Safe" : "URL is Risky");
        response.setSslScore(sslScore);
        response.setPhishingScore(phishingScore);
        response.setDomainReputation(domainReputation);

        // Final Verdict
        if (riskScore < 50) {
            response.setFinalVerdict("Safe");
        } else if (riskScore < 75) {
            response.setFinalVerdict("Suspicious");
        } else {
            response.setFinalVerdict("Dangerous");
        }

        return response;
    }

    private boolean urlExists(String urlString) {
        try {
            if (!urlString.startsWith("http://") && !urlString.startsWith("https://")) {
                urlString = "https://" + urlString;
            }

            URI uri = new URI(urlString);
            HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
            connection.setRequestMethod("HEAD");
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);
            int code = connection.getResponseCode();
            return (200 <= code && code <= 399);
        } catch (Exception e) {
            return false;
        }
    }

}
