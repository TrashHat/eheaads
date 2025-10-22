package com.crossposter;

import com.crossposter.controllers.SceneManager;
import javafx.application.Application;
import javafx.stage.Stage;

public class Main extends Application {

    @Override
    public void start(Stage stage) {
        SceneManager.setStage(stage);

        // Load the home screen
        SceneManager.switchScene("/fxml/home.fxml", "Crossposter");

        // Make window maximized by default
        stage.setMaximized(true);

        stage.setTitle("Crossposter UI");
        stage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}

