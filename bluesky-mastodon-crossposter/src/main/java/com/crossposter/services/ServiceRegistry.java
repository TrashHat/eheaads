package com.crossposter.services;

public class ServiceRegistry {
    private static BlueskyClient blueskyClient = new BlueskyClient();
    private static AuthSession blueskySession;
    private static String blueskyPdsOrigin;

    private static MastodonClient mastodonClient = new MastodonClient();
    private static AuthSession mastodonSession;

    // Bluesky Client
    public static BlueskyClient getBlueskyClient() {
        return blueskyClient;
    }

    // Bluesky Session
    public static AuthSession getBlueskySession() {
        return blueskySession;
    }
    public static void setBlueskySession(AuthSession session) {
        blueskySession = session;
    }

    // Bluesky PDS Origin
    public static String getBlueskyPdsOrigin() {
        return blueskyPdsOrigin;
    }
    public static void setBlueskyPdsOrigin(String pdsOrigin) {
        blueskyPdsOrigin = pdsOrigin;
    }

    // Mastodon Client
    public static MastodonClient getMastodonClient() {
        return mastodonClient;
    }

    // Mastodon Session
    public static AuthSession getMastodonSession() {
        return mastodonSession;
    }
    public static void setMastodonSession(AuthSession session) {
        mastodonSession = session;
    }
}