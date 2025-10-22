package com.crossposter.controllers;

import javafx.event.ActionEvent;
import javafx.scene.input.MouseEvent;

public class SettingsController {

    // ===== Header Navigation =====
    public void openHome(MouseEvent event) {
        System.out.println("[Settings] Navigating to Home...");
        SceneManager.switchScene("/fxml/home.fxml", "Home");
    }

    public void openCreatePost(MouseEvent event) {
        System.out.println("[Settings] Navigating to Create Post...");
        SceneManager.switchScene("/fxml/create_post.fxml", "Create Post");
    }

    // ===== Bluesky Handlers =====
    public void handleReconnectBluesky(ActionEvent event) {
        System.out.println("[Settings] Reconnect Bluesky clicked");
        // TODO: implement Bluesky reconnection logic
    }

    public void handleDisconnectBluesky(ActionEvent event) {
        System.out.println("[Settings] Disconnect Bluesky clicked");
        // TODO: implement Bluesky disconnection logic
    }

    // ===== Mastodon Handlers =====
    public void handleReconnectMastodon(ActionEvent event) {
        System.out.println("[Settings] Reconnect Mastodon clicked");
        // TODO: implement Mastodon reconnection logic
    }

    public void handleDisconnectMastodon(ActionEvent event) {
        System.out.println("[Settings] Disconnect Mastodon clicked");
        // TODO: implement Mastodon disconnection logic
    }
}
