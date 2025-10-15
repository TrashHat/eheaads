// CreatePostController.java

package com.crossposter.controllers;

import com.crossposter.services.AuthSession;
import com.crossposter.services.BlueskyClient;
import com.crossposter.services.MastodonClient; // Add import
import com.crossposter.services.ServiceRegistry;

import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.CheckBox;
import javafx.scene.control.TextArea;
import javafx.scene.input.MouseEvent;

import java.util.Map;

public class CreatePostController {
    private final BlueskyClient blueskyClient = ServiceRegistry.getBlueskyClient();
    private final MastodonClient mastodonClient = ServiceRegistry.getMastodonClient();

    @FXML
    private TextArea postContent;

    @FXML
    private CheckBox blueskyCheck;

    @FXML
    private CheckBox mastodonCheck;

    @FXML
    public void handlePost() {
        String content = postContent.getText();
        boolean postToBluesky = blueskyCheck.isSelected();
        boolean postToMastodon = mastodonCheck.isSelected();

        System.out.println("Submitting post:");
        System.out.println("Content: " + content);
        System.out.println("Bluesky: " + postToBluesky);
        System.out.println("Mastodon: " + postToMastodon);

        boolean allSuccess = true;

        if (postToBluesky) {
            try {
                AuthSession session = ServiceRegistry.getBlueskySession();
                if (session == null || session.accessToken == null) {
                    showAlert(Alert.AlertType.WARNING, "Bluesky not authenticated",
                             "Please authenticate with Bluesky first.");
                    allSuccess = false;
                } else {
                    String pdsOrigin = ServiceRegistry.getBlueskyPdsOrigin();
                    if (pdsOrigin == null) {
                        showAlert(Alert.AlertType.WARNING, "Bluesky PDS Origin Missing",
                                 "Bluesky session lacks PDS origin. Please re-authenticate.");
                        allSuccess = false;
                    } else {
                        Map<String, Object> result = blueskyClient.createPost(session, pdsOrigin, content);
                        System.out.println("Bluesky post result: " + result);
                        showAlert(Alert.AlertType.INFORMATION, "Success", "Posted to Bluesky successfully!");
                    }
                }
            } catch (Exception e) {
                System.err.println("Error posting to Bluesky: " + e.getMessage());
                e.printStackTrace();
                showAlert(Alert.AlertType.ERROR, "Error", "Failed to post to Bluesky: " + e.getMessage());
                allSuccess = false;
            }
        }

        if (postToMastodon) {
            try {
                AuthSession session = ServiceRegistry.getMastodonSession();
                if (session == null || session.accessToken == null || session.instanceUrl == null) {
                    showAlert(Alert.AlertType.WARNING, "Mastodon not authenticated",
                             "Please authenticate with Mastodon first.");
                    allSuccess = false;
                } else {
                    Map<String, Object> result = mastodonClient.postStatus(session, content);
                    System.out.println("Mastodon post result: " + result);
                    showAlert(Alert.AlertType.INFORMATION, "Success", "Posted to Mastodon successfully!");
                }
            } catch (Exception e) {
                System.err.println("Error posting to Mastodon: " + e.getMessage());
                e.printStackTrace();
                showAlert(Alert.AlertType.ERROR, "Error", "Failed to post to Mastodon: " + e.getMessage());
                allSuccess = false;
            }
        }

        if (allSuccess && (postToBluesky || postToMastodon)) {
            postContent.clear();
        }
    }

    private void showAlert(Alert.AlertType type, String title, String message) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    // Shared header
    @FXML
    public void openHome(MouseEvent event) {
        System.out.println("Navigating to Home...");
        SceneManager.switchScene("/fxml/home.fxml", "Home");
    }

    @FXML
    public void openCreatePost(MouseEvent event) {
        System.out.println("Already on Create Post page.");
    }

    @FXML
    public void openSettings(MouseEvent event) {
        System.out.println("Navigating to Settings...");
        SceneManager.switchScene("/fxml/settings.fxml", "Settings");
    }
}