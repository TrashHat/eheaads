package com.crossposter.controllers;

import com.crossposter.services.ServiceRegistry;
import com.crossposter.services.BlueskyClient;
import com.crossposter.services.AuthSession;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.input.MouseEvent;

public class BlueskyController {
    private final BlueskyClient blueskyClient = ServiceRegistry.getBlueskyClient();

    @FXML
    public void openHome(MouseEvent event) {
        System.out.println("[Bluesky] Navigating to Home...");
        SceneManager.switchScene("/fxml/home.fxml", "Home");
    }

    @FXML
    public void openCreatePost(MouseEvent event) {
        System.out.println("[Bluesky] Navigating to Create Post...");
        SceneManager.switchScene("/fxml/create_post.fxml", "Create Post");
    }

    @FXML
    public void openSettings(MouseEvent event) {
        System.out.println("[Bluesky] Navigating to Settings...");
        SceneManager.switchScene("/fxml/settings.fxml", "Settings");
    }

    // Main content action
    @FXML
    public void handleStartOAuth(ActionEvent event) {
        System.out.println("[Bluesky] Authenticate clicked");

        try {
            // Start the OAuth flow
            String pdsOrigin = "https://bsky.social";
            AuthSession session = blueskyClient.startAuth(pdsOrigin);

            // Save the session and PDS origin to the registry
            ServiceRegistry.setBlueskySession(session);
            ServiceRegistry.setBlueskyPdsOrigin(pdsOrigin);

            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setHeaderText("Authentication successful!");
            alert.setContentText("Logged in as DID: " + session.did());
            alert.showAndWait();

            // Redirect user to "Create Post" scene
            SceneManager.switchScene("/fxml/create_post.fxml", "Create Post");

        } catch (Exception e) {
            e.printStackTrace();
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setHeaderText("Authentication failed!");
            alert.setContentText("Error: " + e.getMessage());
            alert.showAndWait();
        }
    }
}
