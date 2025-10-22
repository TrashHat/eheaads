package com.crossposter.utils;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

public class HttpUtil {
    private static final HttpClient CLIENT = HttpClient.newHttpClient();

    // Encode a form body.
    public static String formEncode(Map<String, String> params) {
        return params.entrySet().stream()
                .map(e -> java.net.URLEncoder.encode(e.getKey(), java.nio.charset.StandardCharsets.UTF_8)
                        + "=" + java.net.URLEncoder.encode(e.getValue(), java.nio.charset.StandardCharsets.UTF_8))
                .reduce((a, b) -> a + "&" + b)
                .orElse("");
    }

    // Send a POST with form or JSON body, returns response with headers
    public static HttpResponse<String> postFormWithResponse(String url, Map<String, String> headers, String body) {
        System.out.println("url: " + url + "\nheaders: " + headers + "\nbody: " + body);
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .POST(HttpRequest.BodyPublishers.ofString(body));

            for (Map.Entry<String, String> h : headers.entrySet()) {
                builder.header(h.getKey(), h.getValue());
            }

            return CLIENT.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("HTTP POST failed: " + url, e);
        }
    }

    // Send a GET request with headers, returns response with headers
    public static HttpResponse<String> getWithResponse(String url, Map<String, String> headers) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET();

            for (Map.Entry<String, String> h : headers.entrySet()) {
                builder.header(h.getKey(), h.getValue());
            }

            return CLIENT.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("HTTP GET failed: " + url, e);
        }
    }

    // Send a POST with form or JSON body (original method)
    public static String postForm(String url, Map<String, String> headers, String body) {
        return postFormWithResponse(url, headers, body).body();
    }

    // Send a GET request with headers (original method)
    public static String get(String url, Map<String, String> headers) {
        return getWithResponse(url, headers).body();
    }

    // Extract DPoP nonce from response headers
    public static String extractDpopNonce(HttpResponse<String> response) {
        String nonce = response.headers().firstValue("DPoP-Nonce")
                .orElse(response.headers().firstValue("dpop-nonce").orElse(null));
        return nonce;
    }
}