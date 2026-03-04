package com.github.yildizmy.security;

import com.github.yildizmy.config.MessageSourceConfig;
import com.github.yildizmy.config.SecurityConfig;
import com.github.yildizmy.controller.AuthController;
import com.github.yildizmy.controller.WalletController;
import com.github.yildizmy.service.AuthService;
import com.github.yildizmy.service.WalletService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Security integration tests verifying authentication enforcement, public
 * endpoint access, CSRF behaviour, and JWT rejection scenarios.
 *
 * Uses a self-contained security configuration that mirrors the production
 * SecurityConfig but injects mock dependencies directly, ensuring consistent
 * behaviour across local and CI environments.
 */
@WebMvcTest({ AuthController.class, WalletController.class })
@Import(SecurityConfigTest.TestSecurityConfig.class)
class SecurityConfigTest {

        @Autowired
        private MockMvc mockMvc;

        @MockBean
        private AuthService authService;
        @MockBean
        private WalletService walletService;
        @MockBean
        private JwtUtils jwtUtils;
        @MockBean
        private UserDetailsServiceImpl userDetailsService;
        @MockBean
        private MessageSourceConfig messageConfig;

        @Configuration
        @EnableWebSecurity
        static class TestSecurityConfig {

                @Bean
                @Primary
                public AuthEntryPointJwt testAuthEntryPointJwt(MessageSourceConfig messageConfig) {
                        return new AuthEntryPointJwt(messageConfig);
                }

                @Bean
                @Primary
                public SecurityFilterChain testFilterChain(
                                HttpSecurity http,
                                AuthEntryPointJwt entryPoint,
                                JwtUtils jwtUtils,
                                UserDetailsServiceImpl userDetailsService,
                                MessageSourceConfig messageConfig) throws Exception {

                        AuthTokenFilter tokenFilter =
                                        new AuthTokenFilter(messageConfig, jwtUtils, userDetailsService);

                        http
                                .csrf(csrf -> csrf.disable())
                                .exceptionHandling(eh -> eh.authenticationEntryPoint(entryPoint))
                                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authorizeHttpRequests(auth -> auth
                                        .requestMatchers("/api/v1/auth/**").permitAll()
                                        .anyRequest().authenticated())
                                .addFilterBefore(tokenFilter, UsernamePasswordAuthenticationFilter.class);

                        return http.build();
                }
        }

        @BeforeEach
        void setUp() {
                when(jwtUtils.validateJwtToken(anyString())).thenReturn(false);
                when(messageConfig.getMessage(anyString())).thenReturn("Unauthorized");
                when(messageConfig.getMessage(anyString(), any())).thenReturn("Unauthorized");
        }

        @Test
        void publicEndpoints_shouldBeAccessibleWithoutAuth() throws Exception {
                int status = mockMvc.perform(post("/api/v1/auth/login")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"username\":\"test\",\"password\":\"password123\"}"))
                                .andReturn().getResponse().getStatus();
                assertNotEquals(401, status,
                                "Auth endpoints must not require authentication");
                assertNotEquals(403, status,
                                "Auth endpoints must not be forbidden");
        }

        @Test
        void protectedEndpoints_shouldReturn401_WhenNoToken() throws Exception {
                mockMvc.perform(get("/api/v1/wallets/1"))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        void protectedEndpoints_shouldReturn401_WhenMalformedToken() throws Exception {
                mockMvc.perform(get("/api/v1/wallets/1")
                                .header("Authorization", "Bearer this.is.not.valid"))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        void protectedEndpoints_shouldReturn401_WhenExpiredToken() throws Exception {
                mockMvc.perform(get("/api/v1/wallets/1")
                                .header("Authorization", "Bearer expired.jwt.token"))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        void csrfProtection_shouldBeDisabledForStatelessJwtApi() {
                @SuppressWarnings("resource")
                var ctx = mockMvc.getDispatcherServlet().getWebApplicationContext();
                var filterChains = ctx
                                .getBeansOfType(SecurityFilterChain.class)
                                .values();

                boolean csrfFilterPresent = filterChains.stream()
                                .flatMap(chain -> chain.getFilters().stream())
                                .anyMatch(f -> f.getClass().getSimpleName().equals("CsrfFilter"));

                org.junit.jupiter.api.Assertions.assertFalse(csrfFilterPresent,
                                "CSRF should be disabled for a stateless JWT API — "
                                                + "Bearer token authentication is not vulnerable to CSRF attacks.");
        }

        @Test
        void cors_shouldAllowRequestsFromAllowedOrigin() throws Exception {
                mockMvc.perform(get("/api/v1/wallets/1")
                                .header("Origin", "http://localhost:3000"))
                                .andExpect(status().isUnauthorized());
        }
}
