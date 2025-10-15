// MastodonClient.java

package com.crossposter.services;

import com.crossposter.utils.HttpUtil;
import com.crossposter.utils.LocalCallbackServer;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MastodonClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String CLIENT_NAME = "crossposter";
    private static final String SCOPES = "read write follow";
    private static final String REDIRECT_URI = "http://127.0.0.1:8080/callback";

    private final Map<String, InstanceCredentials> instanceCredentials = new HashMap<>();

    private static class InstanceCredentials {
        final String clientId;
        final String clientSecret;

        InstanceCredentials(String clientId, String clientSecret) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }
    }

    // Regular expression to match a basic handle (username@domain)
    private static final Pattern HANDLE_PATTERN = Pattern.compile("^([^@]+)@([\\w.-]+)$");

    /**
     * Resolves a user-provided handle or instance URL to a canonical instance URL.
     * Supports formats like "user@instance.com", "instance.com", "https://instance.com".
     * @param input The user input (handle or URL).
     * @return The canonical instance URL (e.g., "https://instance.com").
     * @throws IllegalArgumentException If the input cannot be resolved.
     */
    public static String resolveInstanceUrl(String input) throws IllegalArgumentException {
        if (input == null || input.trim().isEmpty()) {
            throw new IllegalArgumentException("Input cannot be null or empty.");
        }

        String trimmedInput = input.trim();

        // Check if it looks like a handle (username@domain)
        Matcher handleMatcher = HANDLE_PATTERN.matcher(trimmedInput);
        if (handleMatcher.matches()) {
            String domain = handleMatcher.group(2);
            // Ensure the domain part doesn't already have a scheme
            if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
                return "https://" + domain;
            } else {
                // If domain part itself looks like a URL, it's likely invalid input
                throw new IllegalArgumentException("Invalid handle format: " + input);
            }
        }

        // Check if it's already a URL (with or without protocol)
        try {
            URI uri = new URI(trimmedInput.startsWith("http") ? trimmedInput : "https://" + trimmedInput);
            String scheme = uri.getScheme();
            String host = uri.getHost();

            if (scheme != null && (scheme.equals("http") || scheme.equals("https")) && host != null) {
                // Reconstruct with https if no scheme was provided or if http was provided
                return "https://" + host;
            } else {
                throw new IllegalArgumentException("Invalid URL format: " + input);
            }
        } catch (Exception e) {
            // If URI parsing fails, it's not a valid URL format either
            throw new IllegalArgumentException("Input is neither a valid handle nor a valid URL: " + input, e);
        }
    }


    public InstanceCredentials registerApp(String instanceUrl) throws Exception {
        String appsEndpoint = instanceUrl + "/api/v1/apps";

        Map<String, String> appParams = Map.of(
                "client_name", CLIENT_NAME,
                "redirect_uris", REDIRECT_URI,
                "scopes", SCOPES
        );

        String requestBody = HttpUtil.formEncode(appParams);
        Map<String, String> headers = Map.of("Content-Type", "application/x-www-form-urlencoded");

        var response = HttpUtil.postFormWithResponse(appsEndpoint, headers, requestBody);

        if (response.statusCode() != 200) {
            throw new IOException("App registration failed with status: " + response.statusCode() + ", body: " + response.body());
        }

        Map<String, Object> appData = MAPPER.readValue(response.body(), Map.class);
        String clientId = (String) appData.get("client_id");
        String clientSecret = (String) appData.get("client_secret");

        if (clientId == null || clientSecret == null) {
            throw new IOException("App registration response missing client_id or client_secret: " + response.body());
        }

        InstanceCredentials creds = new InstanceCredentials(clientId, clientSecret);
        instanceCredentials.put(instanceUrl, creds);
        System.out.println("Registered app on " + instanceUrl + ", Client ID: " + clientId);
        return creds;
    }

    /**
     * Starts the OAuth flow using a user-provided handle or instance URL.
     * Resolves the handle/URL to the instance URL, registers the app if necessary,
     * initiates the browser flow, handles the callback, and exchanges the code for a token.
     * @param userInput The user's handle (e.g., user@instance.com) or instance URL (e.g., instance.com or https://instance.com).
     * @return An AuthSession object containing the access token and resolved instance URL.
     * @throws Exception If the flow fails.
     */
    public AuthSession startAuth(String userInput) throws Exception {
        String instanceUrl = resolveInstanceUrl(userInput);
        System.out.println("Resolved user input '" + userInput + "' to instance URL: " + instanceUrl);

        // Check if credentials are available, register if not
        InstanceCredentials creds = instanceCredentials.get(instanceUrl);
        if (creds == null) {
            creds = registerApp(instanceUrl); // Register dynamically
        }

        String authEndpoint = instanceUrl + "/oauth/authorize";

        String state = UUID.randomUUID().toString();
        String authUrl = authEndpoint +
                "?client_id=" + urlenc(creds.clientId) +
                "&redirect_uri=" + urlenc(REDIRECT_URI) +
                "&response_type=code" +
                "&scope=" + urlenc(SCOPES) +
                "&state=" + urlenc(state);

        LocalCallbackServer callbackServer = new LocalCallbackServer();
        callbackServer.start();
        Desktop.getDesktop().browse(URI.create(authUrl));

        LocalCallbackServer.CallbackResult cb = callbackServer.awaitAuthorizationCode(180);
        callbackServer.stop();

        if (cb == null) {
            throw new IOException("Timeout waiting for OAuth callback.");
        }
        if (!state.equals(cb.state())) {
            throw new IOException("State mismatch during OAuth callback.");
        }

        String tokenEndpoint = instanceUrl + "/oauth/token";
        String tokenBody = String.format(
            "client_id=%s&client_secret=%s&code=%s&grant_type=authorization_code&redirect_uri=%s",
            urlenc(creds.clientId), urlenc(creds.clientSecret), urlenc(cb.code()), urlenc(REDIRECT_URI)
        );

        Map<String, String> tokenHeaders = Map.of(
                "Content-Type", "application/x-www-form-urlencoded"
        );

        var tokenResponse = HttpUtil.postFormWithResponse(tokenEndpoint, tokenHeaders, tokenBody);

        if (tokenResponse.statusCode() != 200) {
            throw new IOException("Token exchange failed with status: " + tokenResponse.statusCode() + ", body: " + tokenResponse.body());
        }

        Map<String, Object> tokenData = MAPPER.readValue(tokenResponse.body(), Map.class);
        String accessToken = (String) tokenData.get("access_token");
        String refreshToken = (String) tokenData.get("refresh_token");
        String tokenType = (String) tokenData.get("token_type");

        if (accessToken == null) {
             throw new IOException("Token exchange response missing access_token: " + tokenResponse.body());
        }
        if (!"Bearer".equalsIgnoreCase(tokenType)) {
             System.out.println("Warning: Expected token_type 'Bearer', got '" + tokenType + "'");
        }

        AuthSession session = new AuthSession(null);
        session.accessToken = accessToken;
        session.refreshToken = refreshToken;
        session.instanceUrl = instanceUrl;

        System.out.println("Successfully authenticated with Mastodon instance: " + instanceUrl);
        return session;
    }

    public Map<String, Object> postStatus(AuthSession session, String content) throws Exception {
        if (session.accessToken == null || session.instanceUrl == null) {
            throw new IllegalStateException("Session is not authenticated or missing instance URL.");
        }

        String postEndpoint = session.instanceUrl + "/api/v1/statuses";

        Map<String, String> headers = Map.of(
                "Authorization", "Bearer " + session.accessToken,
                "Content-Type", "application/json"
        );

        Map<String, Object> postBody = Map.of(
                "status", content,
                "visibility", "public" // Or "unlisted", "private", "direct"
        );

        String jsonBody = MAPPER.writeValueAsString(postBody);

        var postResponse = HttpUtil.postFormWithResponse(postEndpoint, headers, jsonBody);

        if (postResponse.statusCode() != 200) {
             throw new IOException("Post status failed with status: " + postResponse.statusCode() + ", body: " + postResponse.body());
        }

        return MAPPER.readValue(postResponse.body(), Map.class);
    }

    private static String urlenc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}