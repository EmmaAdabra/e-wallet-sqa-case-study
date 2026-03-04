package com.github.yildizmy.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.yildizmy.config.MessageSourceConfig;
import com.github.yildizmy.dto.request.LoginRequest;
import com.github.yildizmy.dto.request.SignupRequest;
import com.github.yildizmy.dto.response.CommandResponse;
import com.github.yildizmy.dto.response.JwtResponse;
import com.github.yildizmy.exception.ElementAlreadyExistsException;
import com.github.yildizmy.security.AuthEntryPointJwt;
import com.github.yildizmy.security.AuthTokenFilter;
import com.github.yildizmy.security.JwtUtils;
import com.github.yildizmy.security.UserDetailsServiceImpl;
import com.github.yildizmy.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for AuthController.
 * Tests the /api/v1/auth/** endpoints (login and signup).
 * These endpoints are on the AUTH_WHITELIST and do not require JWT
 * authentication.
 */
@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private ObjectMapper objectMapper;

        @MockBean
        private AuthService authService;

        // Security infrastructure beans required by Spring Security auto-configuration
        @MockBean
        private JwtUtils jwtUtils;
        @MockBean
        private UserDetailsServiceImpl userDetailsService;
        @MockBean
        private AuthEntryPointJwt authEntryPointJwt;
        @MockBean
        private MessageSourceConfig messageConfig;

        // --- Login tests ---

        @Test
        void login_shouldReturn200_WhenValidCredentials() throws Exception {
                var loginRequest = new LoginRequest("testuser", "password123");
                var jwtResponse = JwtResponse.builder()
                                .type("Bearer")
                                .token("test.jwt.token")
                                .id(1L)
                                .username("testuser")
                                .firstName("Test")
                                .lastName("User")
                                .roles(List.of("ROLE_USER"))
                                .build();

                when(authService.login(any(LoginRequest.class))).thenReturn(jwtResponse);

                mockMvc.perform(post("/api/v1/auth/login")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.token").value("test.jwt.token"))
                                .andExpect(jsonPath("$.username").value("testuser"))
                                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"));
        }

        @Test
        void login_shouldReturn401_WhenInvalidCredentials() throws Exception {
                var loginRequest = new LoginRequest("wronguser", "wrongpassword");

                when(authService.login(any(LoginRequest.class)))
                                .thenThrow(new BadCredentialsException("Bad credentials"));

                mockMvc.perform(post("/api/v1/auth/login")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isUnauthorized());
        }

        // --- Signup tests ---

        @Test
        void signup_shouldReturn201_WhenValidRequest() throws Exception {
                var signupRequest = new SignupRequest(
                                null, "New", "User", "newuser",
                                "newuser@example.com", "password123", Set.of("ROLE_USER"));
                var commandResponse = new CommandResponse(1L);

                when(authService.signup(any(SignupRequest.class))).thenReturn(commandResponse);

                mockMvc.perform(post("/api/v1/auth/signup")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(signupRequest)))
                                .andExpect(status().isCreated())
                                .andExpect(jsonPath("$.id").value(1));
        }

        @Test
        void signup_shouldReturn409_WhenUsernameExists() throws Exception {
                var signupRequest = new SignupRequest(
                                null, "Existing", "User", "existinguser",
                                "existing@example.com", "password123", Set.of("ROLE_USER"));

                when(authService.signup(any(SignupRequest.class)))
                                .thenThrow(new ElementAlreadyExistsException("Username already exists"));

                mockMvc.perform(post("/api/v1/auth/signup")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(signupRequest)))
                                .andExpect(status().isConflict());
        }

        @Test
        void signup_shouldReturn422_WhenInvalidRequest() throws Exception {
                // EP (invalid): missing required fields — username and password are blank,
                // violating @NotBlank and @Size constraints on SignupRequest.
                // Spring Boot 3.x returns 422 (Unprocessable Entity) for validation failures.
                var invalidRequest = new SignupRequest(
                                null, "", "", "", "", "", Set.of());

                mockMvc.perform(post("/api/v1/auth/signup")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(invalidRequest)))
                                .andExpect(status().isUnprocessableEntity());
        }
}
