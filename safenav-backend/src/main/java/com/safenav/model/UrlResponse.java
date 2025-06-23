package com.safenav.model;

public class UrlResponse {
    private boolean safe;
    private int riskScore;
    private String message;

    private int sslScore;
    private int phishingScore;
    private String domainReputation;
    private String finalVerdict;

    // Getters and Setters
    public boolean isSafe() {
        return safe;
    }
    public void setSafe(boolean safe) {
        this.safe = safe;
    }
    public int getRiskScore() {
        return riskScore;
    }
    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }
    public String getMessage() {
        return message;
    }
    public void setMessage(String message) {
        this.message = message;
    }
    public int getSslScore() {
        return sslScore;
    }
    public void setSslScore(int sslScore) {
        this.sslScore = sslScore;
    }
    public int getPhishingScore() {
        return phishingScore;
    }
    public void setPhishingScore(int phishingScore) {
        this.phishingScore = phishingScore;
    }
    public String getDomainReputation() {
        return domainReputation;
    }
    public void setDomainReputation(String domainReputation) {
        this.domainReputation = domainReputation;
    }
    public String getFinalVerdict() {
        return finalVerdict;
    }
    public void setFinalVerdict(String finalVerdict) {
        this.finalVerdict = finalVerdict;
    }
}
