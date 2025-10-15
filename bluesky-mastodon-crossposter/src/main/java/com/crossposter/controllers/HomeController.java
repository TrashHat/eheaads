package com.crossposter.controllers;

import com.crossposter.services.ServiceRegistry;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.input.MouseEvent;

import java.util.Optional;

public class HomeController {

    @FXML
    private Button blueskyButton;

    @FXML
    private Button mastodonButton;

    @FXML
    public void initialize() {
        updateButtons();
    }

    private void updateButtons() {
        if (ServiceRegistry.getBlueskySession() != null) {
            blueskyButton.setText("Disconnect");
            blueskyButton.setStyle("-fx-background-color: red; -fx-text-fill: white; -fx-background-radius: 5;");
        } else {
            blueskyButton.setText("Connect");
            blueskyButton.setStyle("-fx-background-color: #556CFF; -fx-text-fill: white; -fx-background-radius: 5;");
        }

        if (ServiceRegistry.getMastodonSession() != null) {
            mastodonButton.setText("Disconnect");
            mastodonButton.setStyle("-fx-background-color: red; -fx-text-fill: white; -fx-background-radius: 5;");
        } else {
            mastodonButton.setText("Connect");
            mastodonButton.setStyle("-fx-background-color: #556CFF; -fx-text-fill: white; -fx-background-radius: 5;");
        }
    }

    @FXML
    public void openHome(MouseEvent event) {
        System.out.println("Navigating to Home...");
        SceneManager.switchScene("/fxml/home.fxml", "Home");
    }

    @FXML
    public void openCreatePost(MouseEvent event) {
        System.out.println("[Home] Create Post clicked");
        SceneManager.switchScene("/fxml/create_post.fxml", "Create Post");
    }

    @FXML
    public void openBluesky(ActionEvent event) {
        if (ServiceRegistry.getBlueskySession() != null) {
            if (confirmDisconnect("Bluesky")) {
                ServiceRegistry.setBlueskySession(null);
                ServiceRegistry.setBlueskyPdsOrigin(null);
                System.out.println("[Home] Bluesky disconnected.");
                updateButtons();
            }
        } else {
            System.out.println("[Home] BlueSky Connect clicked");
            SceneManager.switchScene("/fxml/bluesky.fxml", "BlueSky Connect");
        }
    }

    @FXML
    public void openMastodon(ActionEvent event) {
        if (ServiceRegistry.getMastodonSession() != null) {
            if (confirmDisconnect("Mastodon")) {
                ServiceRegistry.setMastodonSession(null);
                System.out.println("[Home] Mastodon disconnected.");
                updateButtons();
            }
        } else {
            System.out.println("[Home] Mastodon Connect clicked");
            SceneManager.switchScene("/fxml/mastodon.fxml", "Mastodon Connect");
        }
    }

    @FXML
    public void openSettings(MouseEvent event) {
        System.out.println("[Home] Settings clicked");
        SceneManager.switchScene("/fxml/settings.fxml", "Settings");
    }

    private boolean confirmDisconnect(String platform) {
        Alert alert = new Alert(AlertType.CONFIRMATION);
        alert.setTitle("Confirm Disconnect");
        alert.setHeaderText("Disconnect from " + platform + "?");
        alert.setContentText("Are you sure you want to disconnect your " + platform + " account?");
        Optional<ButtonType> result = alert.showAndWait();
        return result.isPresent() && result.get() == ButtonType.OK;
    }
}
