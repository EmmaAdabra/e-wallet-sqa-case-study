package com.github.yildizmy.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Handles the root path so that visiting the API base URL returns a helpful message
 * instead of requiring authentication. The actual UI is served by the frontend on port 3000.
 */
@RestController
public class RootController {

    @Value("${server.port:8080}")
    private String serverPort;

    @GetMapping("/")
    public ResponseEntity<Map<String, Object>> root() {
        String frontendUrl = "http://localhost:3000";
        return ResponseEntity.ok(Map.of(
                "message", "E-Wallet API is running. Use the frontend to sign in.",
                "api", "http://localhost:" + serverPort,
                "frontend", frontendUrl,
                "docs", "http://localhost:" + serverPort + "/swagger-ui.html"
        ));
    }
}
