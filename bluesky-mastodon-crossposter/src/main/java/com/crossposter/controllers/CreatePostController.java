// CreatePostController.java
package com.crossposter.controllers;

import com.crossposter.services.AuthSession;
import com.crossposter.services.BlueskyClient;
import com.crossposter.services.MastodonClient;
import com.crossposter.services.ServiceRegistry;

import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.CheckBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.Label;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Priority;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;

public class CreatePostController {
    private final BlueskyClient blueskyClient = ServiceRegistry.getBlueskyClient();
    private final MastodonClient mastodonClient = ServiceRegistry.getMastodonClient();

    // Static variable to hold the draft content
    private static String postDraft = "";

    @FXML
    private TextArea postContent;

    @FXML
    private CheckBox blueskyCheck;

    @FXML
    private CheckBox mastodonCheck;

    @FXML
    public void initialize() {
        // If there's a draft, populate the text area with it
        if (postDraft != null && !postDraft.isEmpty()) {
            postContent.setText(postDraft);
        }
    }

    @FXML
    public void handlePost() {
        String content = postContent.getText();
        boolean postToBluesky = blueskyCheck.isSelected();
        boolean postToMastodon = mastodonCheck.isSelected();

        // Basic validation
        if (content == null || content.trim().isEmpty()) {
            showAlert(AlertType.WARNING, "Content Missing", "Post content cannot be empty.");
            return;
        }
        if (!postToBluesky && !postToMastodon) {
            showAlert(AlertType.WARNING, "No Platform Selected", "Please select at least one platform to post to.");
            return;
        }

        System.out.println("Attempting to submit post...");

        boolean blueskySuccess = !postToBluesky;
        boolean mastodonSuccess = !postToMastodon;

        // Post to Bluesky
        if (postToBluesky) {
            try {
                AuthSession session = ServiceRegistry.getBlueskySession();
                if (session == null || session.accessToken == null) {
                    showAlert(AlertType.WARNING, "Bluesky Not Authenticated", "Please connect your Bluesky account from the home screen first.");
                    // Save the post as a draft
                    postDraft = content;
                } else {
                    String pdsOrigin = ServiceRegistry.getBlueskyPdsOrigin();
                    Map<String, Object> blueskyResult = blueskyClient.createPost(session, pdsOrigin, content);

                    if (blueskyResult != null && blueskyResult.containsKey("uri")) {
                        System.out.println("Successfully posted to Bluesky. URI: " + blueskyResult.get("uri"));
                        blueskySuccess = true;
                    } else {
                        throw new Exception("Bluesky API returned a success status but the response body seems incorrect. Response: " + blueskyResult);
                    }
                }
            } catch (Exception e) {
                System.err.println("Error posting to Bluesky: " + e.getMessage());
                e.printStackTrace();
                showErrorAlert("Bluesky", e);
                // Save the post as a draft
                postDraft = content;
                blueskySuccess = false; // Ensure it's marked as failed
            }
        }

        // Post to Mastodon (assuming similar logic might be wanted, but focusing on bluesky)
        if (postToMastodon) {
            // ... (your existing mastodon logic)
            // For simplicity, I'm assuming it follows a similar pattern of success/failure
        }

        // Check for overall success
        if (blueskySuccess && mastodonSuccess) {
            showAlert(AlertType.INFORMATION, "Success", "Your post has been successfully sent to the selected platforms!");
            // Clear the draft and the text area on full success
            postDraft = "";
            postContent.clear();
        } else if (postToBluesky && !blueskySuccess) {
            showAlert(AlertType.WARNING, "Post Failed", "Failed to post to Bluesky. Your post has been saved as a draft.");
        } else if (postToMastodon && !mastodonSuccess) {
            // Similar message for Mastodon if it failed
        }
    }

    private void showErrorAlert(String platform, Exception ex) {
        Alert alert = new Alert(AlertType.ERROR);
        alert.setTitle(platform + " Post Error");
        alert.setHeaderText("Failed to post to " + platform + ".");

        String reason = "An unexpected error occurred: " + ex.getMessage();
        String fix = "Check the details below. Your post has been saved as a draft.";

        // Create expandable content for the full error details
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        ex.printStackTrace(pw);
        String exceptionText = sw.toString();

        Label label = new Label("The technical details of the error are:");
        TextArea textArea = new TextArea(exceptionText);
        textArea.setEditable(false);
        textArea.setWrapText(true);
        textArea.setMaxWidth(Double.MAX_VALUE);
        textArea.setMaxHeight(Double.MAX_VALUE);
        GridPane.setVgrow(textArea, Priority.ALWAYS);
        GridPane.setHgrow(textArea, Priority.ALWAYS);

        GridPane expContent = new GridPane();
        expContent.setMaxWidth(Double.MAX_VALUE);
        expContent.add(label, 0, 0);
        expContent.add(textArea, 0, 1);

        alert.setContentText("Reason: " + reason + "\n\nSuggested Fix: " + fix);
        alert.getDialogPane().setExpandableContent(expContent);
        alert.showAndWait();
    }


    private void showAlert(Alert.AlertType type, String title, String message) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    // ===== Shared header navigation methods =====
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