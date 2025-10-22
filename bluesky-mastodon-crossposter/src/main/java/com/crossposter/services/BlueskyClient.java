// BlueskyClient.java
package com.crossposter.services;

import com.crossposter.utils.DPoPUtil;
import com.crossposter.utils.HttpUtil;
import com.crossposter.utils.LocalCallbackServer;
import com.crossposter.utils.PkceUtil;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.net.http.HttpResponse;

public class BlueskyClient {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String CLIENT_ID = "https://bcala06.github.io/bluesky-mastodon-crossposter/client-metadata.json";
    private static final String REDIRECT_URI = "http://127.0.0.1:8080/callback";
    private static final String SCOPE = "atproto";

    public AuthSession startAuth(String pdsOrigin) throws Exception {
        // ... (existing startAuth method remains the same)
        String metaUrl = pdsOrigin + "/.well-known/oauth-authorization-server";
        String metaBody = HttpUtil.get(metaUrl, Map.of("Accept", "application/json"));
        Map<String, Object> meta = MAPPER.readValue(metaBody, Map.class);
        String parEndpoint = (String) meta.get("pushed_authorization_request_endpoint");
        String authEndpoint = (String) meta.get("authorization_endpoint");
        String tokenEndpoint = (String) meta.get("token_endpoint");
        String codeVerifier = PkceUtil.generateCodeVerifier();
        String codeChallenge = PkceUtil.generateCodeChallenge(codeVerifier);
        DPoPUtil.init();
        AuthSession session = new AuthSession(codeVerifier);
        String state = UUID.randomUUID().toString();
        String parBody = String.format(
                "client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
                urlenc(CLIENT_ID), urlenc(REDIRECT_URI), urlenc(SCOPE), urlenc(state), urlenc(codeChallenge), urlenc("S256")
        );

        String dpop1 = DPoPUtil.buildDPoP("POST", parEndpoint, session.dpopNonce, null);
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("DPoP", dpop1);
        var parResponse = HttpUtil.postFormWithResponse(parEndpoint, headers, parBody);
        int statusCode = parResponse.statusCode();
        boolean needsRetry = (statusCode == 401) || (statusCode == 400 && parResponse.body().contains("\"use_dpop_nonce\""));
        if (needsRetry) {
            String nonce = HttpUtil.extractDpopNonce(parResponse);
            if (nonce != null && !nonce.isEmpty()) {
                session.dpopNonce = nonce;
                String dpop2 = DPoPUtil.buildDPoP("POST", parEndpoint, session.dpopNonce, null);
                headers.put("DPoP", dpop2);
                parResponse = HttpUtil.postFormWithResponse(parEndpoint, headers, parBody);
            }
        }
        String newNonce = HttpUtil.extractDpopNonce(parResponse);
        if (newNonce != null) { session.dpopNonce = newNonce; }
        if (parResponse.statusCode() != 200 && parResponse.statusCode() != 201) {
            throw new IOException("PAR failed with status " + parResponse.statusCode() + ": " + parResponse.body());
        }
        Map<String, Object> parJson = MAPPER.readValue(parResponse.body(), Map.class);
        String requestUri = (String) parJson.get("request_uri");
        if (requestUri == null || requestUri.trim().isEmpty()) {
            throw new IOException("PAR failed, no request_uri returned: " + parResponse.body());
        }
        String authUrl = authEndpoint + "?client_id=" + urlenc(CLIENT_ID) + "&request_uri=" + urlenc(requestUri) + "&state=" + urlenc(state);
        LocalCallbackServer callbackServer = new LocalCallbackServer();
        callbackServer.start();
        Desktop.getDesktop().browse(URI.create(authUrl));
        LocalCallbackServer.CallbackResult cb = callbackServer.awaitAuthorizationCode(180);
        callbackServer.stop();
        if (cb == null) throw new IOException("Timeout waiting for callback");
        if (!state.equals(cb.state())) throw new IOException("State mismatch");
        String code = cb.code();
        String tokenBody = String.format(
                "grant_type=authorization_code&code=%s&redirect_uri=%s&code_verifier=%s&client_id=%s",
                urlenc(code), urlenc(REDIRECT_URI), urlenc(codeVerifier), urlenc(CLIENT_ID)
        );

        String tokenDpop = DPoPUtil.buildDPoP("POST", tokenEndpoint, session.dpopNonce, null);
        headers.clear();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("DPoP", tokenDpop);
        var tokenResponse = HttpUtil.postFormWithResponse(tokenEndpoint, headers, tokenBody);
        newNonce = HttpUtil.extractDpopNonce(tokenResponse);
        if (newNonce != null) { session.dpopNonce = newNonce; }
        Map<String, Object> tokenJson = MAPPER.readValue(tokenResponse.body(), Map.class);
        String error = (String) tokenJson.get("error");
        if (error != null) {
            String errorDescription = (String) tokenJson.get("error_description");
            throw new IOException("Token Exchange Error: " + error + (errorDescription != null ? " - " + errorDescription : ""));
        }
        session.accessToken = (String) tokenJson.get("access_token");
        session.refreshToken = (String) tokenJson.get("refresh_token");
        session.did = extractClaimFromToken(session.accessToken, "sub");
        if (session.did == null || !session.did.startsWith("did:")) {
            throw new IOException("Could not extract DID (sub) from access token");
        }
        String pdsDid = extractClaimFromToken(session.accessToken, "aud");
        if (pdsDid == null || !pdsDid.startsWith("did:web:")) {
            throw new IOException("Could not extract PDS (aud) from access token");
        }
        session.issuer = "https://" + pdsDid.substring("did:web:".length());
        System.out.println("Discovered user PDS Origin from token 'aud' claim: " + session.issuer);
        return session;

    }

    private String extractClaimFromToken(String accessToken, String claimName) {
        try {
            String[] parts = accessToken.split("\\.");
            if (parts.length >= 2) {
                String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
                Map<String, Object> claims = MAPPER.readValue(payload, Map.class);
                Object claimValue = claims.get(claimName);
                if (claimValue != null) { return claimValue.toString(); }
            }
        } catch (Exception e) {
            System.err.println("Could not extract claim '" + claimName + "' from token: " + e.getMessage());
        }
        return null;
    }

    public Map<String, Object> createPost(AuthSession session, String pdsOrigin, String text) throws Exception {
        if (session.did == null || session.did.isBlank()) {
            throw new IllegalStateException("AuthSession has no DID. Make sure to set it after login.");
        }
        String url = pdsOrigin + "/xrpc/com.atproto.repo.createRecord";
        Map<String, Object> record = Map.of(
                "text", text,
                "$type", "app.bsky.feed.post",
                "createdAt", Instant.now().toString()
        );
        Map<String, Object> body = new HashMap<>();
        body.put("repo", session.did);
        body.put("collection", "app.bsky.feed.post");
        body.put("record", record);
        String jsonBody = MAPPER.writeValueAsString(body);

        String dpop = DPoPUtil.buildDPoP("POST", url, session.dpopNonce, session.accessToken);
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "DPoP " + session.accessToken);
        headers.put("DPoP", dpop);
        headers.put("Content-Type", "application/json");

        HttpResponse<String> response = HttpUtil.postFormWithResponse(url, headers, jsonBody);

        // Handle DPoP nonce challenge
        if (response.statusCode() == 401 && response.body().contains("use_dpop_nonce")) {
            String newNonce = HttpUtil.extractDpopNonce(response);
            if (newNonce != null && !newNonce.isBlank()) {
                session.dpopNonce = newNonce;
                dpop = DPoPUtil.buildDPoP("POST", url, newNonce, session.accessToken);
                headers.put("DPoP", dpop);
                response = HttpUtil.postFormWithResponse(url, headers, jsonBody);
            }
        }

        if (response.statusCode() >= 400) {
            throw new IOException("Failed to post to Bluesky. Status: " + response.statusCode() + ", Body: " + response.body());
        }

        return MAPPER.readValue(response.body(), Map.class);
    }

    private static String urlenc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}