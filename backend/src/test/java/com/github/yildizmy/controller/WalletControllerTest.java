package com.github.yildizmy.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.yildizmy.config.MessageSourceConfig;
import com.github.yildizmy.dto.request.TransactionRequest;
import com.github.yildizmy.dto.request.WalletRequest;
import com.github.yildizmy.dto.response.CommandResponse;
import com.github.yildizmy.dto.response.WalletResponse;
import com.github.yildizmy.exception.InsufficientFundsException;
import com.github.yildizmy.exception.NoSuchElementFoundException;
import com.github.yildizmy.security.AuthEntryPointJwt;
import com.github.yildizmy.security.JwtUtils;
import com.github.yildizmy.security.UserDetailsServiceImpl;
import com.github.yildizmy.service.WalletService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for WalletController.
 * Tests the /api/v1/wallets/** endpoints (CRUD, transfer, addFunds,
 * withdrawFunds).
 * All endpoints require ROLE_USER via @PreAuthorize.
 */
@WebMvcTest(WalletController.class)
class WalletControllerTest {

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private ObjectMapper objectMapper;

        @MockBean
        private WalletService walletService;

        // Security infrastructure beans
        @MockBean
        private JwtUtils jwtUtils;
        @MockBean
        private UserDetailsServiceImpl userDetailsService;
        @MockBean
        private AuthEntryPointJwt authEntryPointJwt;
        @MockBean
        private MessageSourceConfig messageConfig;

        // --- Authentication enforcement tests ---

        @Test
        void findById_shouldReturn401_WhenNoToken() throws Exception {
                // Security: unauthenticated request to a protected endpoint must be rejected
                mockMvc.perform(get("/api/v1/wallets/1"))
                                .andExpect(status().isUnauthorized());
        }

        // --- Authenticated endpoint tests ---

        @Test
        @WithMockUser(roles = "USER")
        void findById_shouldReturn200_WhenAuthenticated() throws Exception {
                var response = new WalletResponse();
                response.setId(1L);
                response.setIban("TEST123");
                response.setName("Test Wallet");
                response.setBalance(BigDecimal.valueOf(1000));

                when(walletService.findById(1L)).thenReturn(response);

                mockMvc.perform(get("/api/v1/wallets/1"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.id").value(1))
                                .andExpect(jsonPath("$.iban").value("TEST123"))
                                .andExpect(jsonPath("$.balance").value(1000));
        }

        @Test
        @WithMockUser(roles = "USER")
        void findById_shouldReturn404_WhenWalletNotFound() throws Exception {
                when(walletService.findById(99L))
                                .thenThrow(new NoSuchElementFoundException("Wallet not found"));

                mockMvc.perform(get("/api/v1/wallets/99"))
                                .andExpect(status().isNotFound());
        }

        @Test
        @WithMockUser(roles = "USER")
        void create_shouldReturn201_WhenValidRequest() throws Exception {
                var request = new WalletRequest();
                request.setUserId(1L);
                request.setIban("DE89370400440532013000");
                request.setName("My Wallet");
                request.setBalance(BigDecimal.valueOf(500));

                when(walletService.create(any(WalletRequest.class)))
                                .thenReturn(new CommandResponse(1L));

                mockMvc.perform(post("/api/v1/wallets")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isCreated())
                                .andExpect(jsonPath("$.id").value(1));
        }

        @Test
        @WithMockUser(roles = "USER")
        void transferFunds_shouldReturn201_WhenValid() throws Exception {
                var request = new TransactionRequest();
                request.setAmount(BigDecimal.valueOf(100));
                request.setFromWalletIban("FROM123");
                request.setToWalletIban("TO456");
                request.setTypeId(1L);

                when(walletService.transferFunds(any(TransactionRequest.class)))
                                .thenReturn(new CommandResponse(1L));

                mockMvc.perform(post("/api/v1/wallets/transfer")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isCreated())
                                .andExpect(jsonPath("$.id").value(1));
        }

        @Test
        @WithMockUser(roles = "USER")
        void transferFunds_shouldReturn412_WhenInsufficientFunds() throws Exception {
                var request = new TransactionRequest();
                request.setAmount(BigDecimal.valueOf(99999));
                request.setFromWalletIban("FROM123");
                request.setToWalletIban("TO456");
                request.setTypeId(1L);

                when(walletService.transferFunds(any(TransactionRequest.class)))
                                .thenThrow(new InsufficientFundsException("Insufficient funds"));

                mockMvc.perform(post("/api/v1/wallets/transfer")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isPreconditionFailed());
        }

        @Test
        @WithMockUser(roles = "USER")
        void addFunds_shouldReturn201_WhenValid() throws Exception {
                var request = new TransactionRequest();
                request.setAmount(BigDecimal.valueOf(200));
                request.setFromWalletIban("FROM123");
                request.setToWalletIban("TO456");
                request.setTypeId(1L);

                when(walletService.addFunds(any(TransactionRequest.class)))
                                .thenReturn(new CommandResponse(1L));

                mockMvc.perform(post("/api/v1/wallets/addFunds")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isCreated())
                                .andExpect(jsonPath("$.id").value(1));
        }

        @Test
        @WithMockUser(roles = "USER")
        void withdrawFunds_shouldReturn201_WhenValid() throws Exception {
                var request = new TransactionRequest();
                request.setAmount(BigDecimal.valueOf(100));
                request.setFromWalletIban("FROM123");
                request.setToWalletIban("TO456");
                request.setTypeId(1L);

                when(walletService.withdrawFunds(any(TransactionRequest.class)))
                                .thenReturn(new CommandResponse(1L));

                mockMvc.perform(post("/api/v1/wallets/withdrawFunds")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isCreated())
                                .andExpect(jsonPath("$.id").value(1));
        }

        @Test
        @WithMockUser(roles = "USER")
        void deleteById_shouldReturn204_WhenValid() throws Exception {
                doNothing().when(walletService).deleteById(1L);

                mockMvc.perform(delete("/api/v1/wallets/1")
                                .with(csrf()))
                                .andExpect(status().isNoContent());
        }
}
