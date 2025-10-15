package com.crossposter.services;

public class AuthSession {
    public final String codeVerifier;
    public String instanceUrl;
    public String issuer;
    public String dpopNonce;
    public String accessToken;
    public String refreshToken;
    public String did;
    

    public AuthSession(String codeVerifier) {
        this.codeVerifier = codeVerifier;
    }

    public String accessToken() {
        return accessToken;
    }

    public String refreshToken() {
        return refreshToken;
    }

    public String did() {
        return did;
    }
}
