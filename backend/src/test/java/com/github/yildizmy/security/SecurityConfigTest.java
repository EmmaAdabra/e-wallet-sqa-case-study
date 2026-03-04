package com.github.yildizmy.security;

import com.github.yildizmy.config.MessageSourceConfig;
import com.github.yildizmy.controller.AuthController;
import com.github.yildizmy.controller.WalletController;
import com.github.yildizmy.service.AuthService;
import com.github.yildizmy.service.WalletService;
import com.github.yildizmy.config.SecurityConfig;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Security integration tests verifying the SecurityConfig filter chain.
 * Tests authentication enforcement, public endpoint access, CSRF behaviour,
 * and JWT rejection scenarios.
 */
@WebMvcTest({ AuthController.class, WalletController.class })
@Import({ SecurityConfig.class, SecurityConfigTest.EntryPointConfig.class })
class SecurityConfigTest {

        @Autowired
        private MockMvc mockMvc;

        // Service mocks
        @MockBean
        private AuthService authService;
        @MockBean
        private WalletService walletService;

        // Security infrastructure beans
        @MockBean
        private JwtUtils jwtUtils;
        @MockBean
        private UserDetailsServiceImpl userDetailsService;
        @MockBean
        private MessageSourceConfig messageConfig;

        /**
         * Supplies the real AuthEntryPointJwt so the filter chain always returns 401
         * when unauthenticated (avoids mock not invoked in CI).
         */
        static class EntryPointConfig {
                @Bean
                @Primary
                public AuthEntryPointJwt authEntryPointJwt(MessageSourceConfig messageConfig) {
                        return new AuthEntryPointJwt(messageConfig);
                }
        }

        @BeforeEach
        void setUp() {
                lenient().when(jwtUtils.validateJwtToken(anyString())).thenReturn(false);
                when(messageConfig.getMessage(anyString())).thenReturn("Unauthorized");
                when(messageConfig.getMessage(anyString(), any())).thenReturn("Unauthorized");
        }

        // --- Public endpoint access ---

        @Test
        void publicEndpoints_shouldBeAccessibleWithoutAuth() throws Exception {
                mockMvc.perform(post("/api/v1/auth/login")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"username\":\"test\",\"password\":\"password123\"}"))
                                .andExpect(status().isOk());
        }

        // --- Protected endpoint access ---

        @Test
        void protectedEndpoints_shouldReturn401_WhenNoToken() throws Exception {
                // All /api/v1/wallets/** endpoints require authentication
                mockMvc.perform(get("/api/v1/wallets/1"))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        void protectedEndpoints_shouldReturn401_WhenMalformedToken() throws Exception {
                // A malformed Bearer token should be rejected by the AuthTokenFilter
                mockMvc.perform(get("/api/v1/wallets/1")
                                .header("Authorization", "Bearer this.is.not.valid"))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        void protectedEndpoints_shouldReturn401_WhenExpiredToken() throws Exception {
                // An expired token header should be rejected
                mockMvc.perform(get("/api/v1/wallets/1")
                                .header("Authorization", "Bearer expired.jwt.token"))
                                .andExpect(status().isUnauthorized());
        }

        // --- CSRF behaviour ---

        @Autowired
        private org.springframework.context.ApplicationContext applicationContext;

        @Test
        void csrfProtection_shouldBeDisabledForStatelessJwtApi() {
                var filterChains = applicationContext
                                .getBeansOfType(org.springframework.security.web.SecurityFilterChain.class)
                                .values();

                boolean csrfFilterPresent = filterChains.stream()
                                .flatMap(chain -> chain.getFilters().stream())
                                .anyMatch(filter -> filter.getClass().getSimpleName().equals("CsrfFilter"));

                org.junit.jupiter.api.Assertions.assertFalse(csrfFilterPresent,
                                "CSRF should be disabled for a stateless JWT API — "
                                                + "Bearer token authentication is not vulnerable to CSRF attacks.");
        }

        // --- CORS behaviour ---

        @Test
        void cors_shouldAllowRequestsFromAllowedOrigin() throws Exception {
                // SecurityConfig allows requests from http://localhost:3000
                mockMvc.perform(get("/api/v1/wallets/1")
                                .header("Origin", "http://localhost:3000"))
                                .andExpect(status().isUnauthorized()); // auth failure, but NOT CORS rejection
        }
}
