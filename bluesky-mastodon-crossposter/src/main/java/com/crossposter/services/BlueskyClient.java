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

public class BlueskyClient {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String CLIENT_ID = "https://bcala06.github.io/bluesky-mastodon-crossposter/client-metadata.json";
    private static final String REDIRECT_URI = "http://127.0.0.1:8080/callback";
    private static final String SCOPE = "atproto";

    public AuthSession startAuth(String pdsOrigin) throws Exception {
        // Discover authorization server metadata
        String metaUrl = pdsOrigin + "/.well-known/oauth-authorization-server";
        String metaBody = HttpUtil.get(metaUrl, Map.of("Accept", "application/json"));
        Map<String, Object> meta = MAPPER.readValue(metaBody, Map.class);

        String parEndpoint = (String) meta.get("pushed_authorization_request_endpoint");
        String authEndpoint = (String) meta.get("authorization_endpoint");
        String tokenEndpoint = (String) meta.get("token_endpoint");

        // PKCE setup
        String codeVerifier = PkceUtil.generateCodeVerifier();
        String codeChallenge = PkceUtil.generateCodeChallenge(codeVerifier);

        // Init DPoP keypair
        DPoPUtil.init();
        AuthSession session = new AuthSession(codeVerifier);

        // Build PAR request
        String state = UUID.randomUUID().toString();
        String parBody = String.format(
            "client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
            urlenc(CLIENT_ID), urlenc(REDIRECT_URI), urlenc(SCOPE), urlenc(state), urlenc(codeChallenge), urlenc("S256")
        );

        // First PAR attempt
        String dpop1 = DPoPUtil.buildDPoP("POST", parEndpoint, session.dpopNonce);
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("DPoP", dpop1);
        
        var parResponse = HttpUtil.postFormWithResponse(parEndpoint, headers, parBody);
        
        // Check if we need to retry with nonce (401 or 400 with use_dpop_nonce)
        int statusCode = parResponse.statusCode();
        boolean needsRetry = (statusCode == 401) || 
                           (statusCode == 400 && parResponse.body().contains("\"use_dpop_nonce\""));
        
        if (needsRetry) {
            String nonce = HttpUtil.extractDpopNonce(parResponse);
            if (nonce != null && !nonce.isEmpty()) {
                session.dpopNonce = nonce;
                String dpop2 = DPoPUtil.buildDPoP("POST", parEndpoint, session.dpopNonce);
                
                headers.put("DPoP", dpop2);
                parResponse = HttpUtil.postFormWithResponse(parEndpoint, headers, parBody);
            }
        }

        // Update DPoP nonce if provided in final response
        String newNonce = HttpUtil.extractDpopNonce(parResponse);
        if (newNonce != null) {
            session.dpopNonce = newNonce;
        }

        if (parResponse.statusCode() != 200 && parResponse.statusCode() != 201) {
            throw new IOException("PAR failed with status " + parResponse.statusCode() + ": " + parResponse.body());
        }

        Map<String, Object> parJson = MAPPER.readValue(parResponse.body(), Map.class);
        String requestUri = (String) parJson.get("request_uri");
        if (requestUri == null || requestUri.trim().isEmpty()) {
            throw new IOException("PAR failed, no request_uri returned: " + parResponse.body());
        }

        // Open system browser to authorization URL
        String authUrl = authEndpoint
                + "?client_id=" + urlenc(CLIENT_ID)
                + "&request_uri=" + urlenc(requestUri)
                + "&state=" + urlenc(state);

        LocalCallbackServer callbackServer = new LocalCallbackServer();
        callbackServer.start();
        Desktop.getDesktop().browse(URI.create(authUrl));

        LocalCallbackServer.CallbackResult cb = callbackServer.awaitAuthorizationCode(180);
        callbackServer.stop();
        if (cb == null) throw new IOException("Timeout waiting for callback");
        if (!state.equals(cb.state())) throw new IOException("State mismatch");
        String code = cb.code();

        // Token exchange
        String tokenBody = String.format(
            "grant_type=authorization_code&code=%s&redirect_uri=%s&code_verifier=%s&client_id=%s",
            urlenc(code), urlenc(REDIRECT_URI), urlenc(codeVerifier), urlenc(CLIENT_ID)
        );
        
        String tokenDpop = DPoPUtil.buildDPoP("POST", tokenEndpoint, session.dpopNonce);

        headers.clear();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("DPoP", tokenDpop);

        var tokenResponse = HttpUtil.postFormWithResponse(tokenEndpoint, headers, tokenBody);
        
        // Update DPoP nonce if provided in response
        newNonce = HttpUtil.extractDpopNonce(tokenResponse);
        if (newNonce != null) {
            session.dpopNonce = newNonce;
        }

        Map<String, Object> tokenJson = MAPPER.readValue(tokenResponse.body(), Map.class);
        
        // Check for errors
        String error = (String) tokenJson.get("error");
        if (error != null) {
            String errorDescription = (String) tokenJson.get("error_description");
            throw new IOException("Token Exchange Error: " + error + 
                (errorDescription != null ? " - " + errorDescription : ""));
        }

        session.accessToken = (String) tokenJson.get("access_token");
        session.refreshToken = (String) tokenJson.get("refresh_token");

        // Extract DID from the JWT token (the 'sub' claim)
        session.did = extractDidFromToken(session.accessToken);
        if (session.did == null) {
            throw new IOException("Could not extract DID from access token");
        }

        return session;
    }

    private String extractDidFromToken(String accessToken) {
        try {
            // JWT has 3 parts separated by dots
            String[] parts = accessToken.split("\\.");
            if (parts.length >= 2) {
                // Decode the payload (second part)
                String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
                Map<String, Object> claims = MAPPER.readValue(payload, Map.class);
                Object sub = claims.get("sub");
                if (sub != null && sub.toString().startsWith("did:")) {
                    return sub.toString();
                }
            }
        } catch (Exception e) {
            System.out.println("Could not extract DID from token: " + e.getMessage());
        }
        return null;
    }

    public Map<String, Object> createPost(AuthSession session, String pdsOrigin, String text) throws Exception {
        if (session.did == null || session.did.isBlank()) {
            throw new IllegalStateException("AuthSession has no DID. Make sure to set it after login.");
        }

        String url = pdsOrigin + "/xrpc/com.atproto.repo.createRecord";

        // Build record payload
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

        // DPoP proof for this request
        String dpop = DPoPUtil.buildDPoP("POST", url, session.dpopNonce);

        Map<String, String> headers = Map.of(
                "Authorization", "DPoP " + session.accessToken,
                "DPoP", dpop,
                "Content-Type", "application/json"
        );

        var postResponse = HttpUtil.postFormWithResponse(url, headers, jsonBody);
        
        // Update DPoP nonce if provided in response
        String newNonce = HttpUtil.extractDpopNonce(postResponse);
        if (newNonce != null) {
            session.dpopNonce = newNonce;
        }

        return MAPPER.readValue(postResponse.body(), Map.class);
    }

    private static String urlenc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}