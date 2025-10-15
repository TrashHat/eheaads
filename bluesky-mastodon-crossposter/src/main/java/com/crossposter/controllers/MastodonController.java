package com.crossposter.controllers;

import com.crossposter.services.MastodonClient;
import com.crossposter.services.ServiceRegistry;
import com.crossposter.services.AuthSession;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;

public class MastodonController {

    private final MastodonClient mastodonClient = ServiceRegistry.getMastodonClient();

    @FXML
    private TextField mastodonHandleField;

    public void openHome(MouseEvent event) {
        System.out.println("[Mastodon] Navigating to Home...");
        SceneManager.switchScene("/fxml/home.fxml", "Home");
    }

    public void openCreatePost(MouseEvent event) {
        System.out.println("[Mastodon] Navigating to Create Post...");
        SceneManager.switchScene("/fxml/create_post.fxml", "Create Post");
    }

    public void openSettings(MouseEvent event) {
        System.out.println("[Mastodon] Navigating to Settings...");
        SceneManager.switchScene("/fxml/settings.fxml", "Settings");
    }

    // Main content action
    public void handleAuthentication(ActionEvent event) {
        System.out.println("[Mastodon] Authenticate clicked");

        String userInput = mastodonHandleField.getText();
        if (userInput == null || userInput.trim().isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setHeaderText("Input Required");
            alert.setContentText("Please enter your Mastodon handle or instance.");
            alert.showAndWait();
            return;
        }

        try {
            // Start the OAuth flow using the user's input
            AuthSession session = mastodonClient.startAuth(userInput);
            ServiceRegistry.setMastodonSession(session);

            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setHeaderText("Authentication successful!");
            alert.setContentText("Logged in to instance: " + session.instanceUrl);
            alert.showAndWait();

            // Redirect user back to Home (so button updates)
            SceneManager.switchScene("/fxml/home.fxml", "Home");

        } catch (Exception e) {
            e.printStackTrace();
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setHeaderText("Authentication failed!");
            alert.setContentText("Error: " + e.getMessage());
            alert.showAndWait();
        }
    }
}
