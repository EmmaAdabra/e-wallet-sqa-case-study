package com.github.yildizmy.controller;

import com.github.yildizmy.config.MessageSourceConfig;
import com.github.yildizmy.dto.response.TransactionResponse;
import com.github.yildizmy.security.AuthEntryPointJwt;
import com.github.yildizmy.security.JwtUtils;
import com.github.yildizmy.security.UserDetailsServiceImpl;
import com.github.yildizmy.service.TransactionService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for TransactionController.
 * Tests the /api/v1/transactions/** endpoints (all GET, all require ROLE_USER).
 */
@WebMvcTest(TransactionController.class)
class TransactionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private TransactionService transactionService;

    // Security infrastructure beans
    @MockBean
    private JwtUtils jwtUtils;
    @MockBean
    private UserDetailsServiceImpl userDetailsService;
    @MockBean
    private AuthEntryPointJwt authEntryPointJwt;
    @MockBean
    private MessageSourceConfig messageConfig;

    // --- Authentication enforcement ---

    @Test
    void findById_shouldReturn401_WhenNoToken() throws Exception {
        mockMvc.perform(get("/api/v1/transactions/1"))
                .andExpect(status().isUnauthorized());
    }

    // --- Authenticated endpoint tests ---

    @Test
    @WithMockUser(roles = "USER")
    void findById_shouldReturn200_WhenAuthenticated() throws Exception {
        var response = new TransactionResponse();
        response.setId(1L);
        response.setAmount(BigDecimal.valueOf(100));
        response.setReferenceNumber(UUID.fromString("550e8400-e29b-41d4-a716-446655440000"));

        when(transactionService.findById(1L)).thenReturn(response);

        mockMvc.perform(get("/api/v1/transactions/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.amount").value(100));
    }

    @Test
    @WithMockUser(roles = "USER")
    void findAll_shouldReturn200_WhenAuthenticated() throws Exception {
        var response = new TransactionResponse();
        response.setId(1L);
        response.setAmount(BigDecimal.valueOf(100));

        var page = new PageImpl<>(List.of(response));

        when(transactionService.findAll(any(Pageable.class))).thenReturn(page);

        mockMvc.perform(get("/api/v1/transactions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].id").value(1));
    }
}
