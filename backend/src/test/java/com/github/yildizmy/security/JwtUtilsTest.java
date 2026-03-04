package com.github.yildizmy.security;

import com.github.yildizmy.config.MessageSourceConfig;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for JwtUtils.
 * Techniques used: Happy path, Equivalence Partitioning (EP), Boundary Value Analysis (BVA).
 * @Value fields (jwtSecret, jwtExpirationMs) are injected via ReflectionTestUtils.
 */
@ExtendWith(MockitoExtension.class)
class JwtUtilsTest {

    @InjectMocks
    private JwtUtils jwtUtils;

    @Mock
    private MessageSourceConfig messageConfig;

    // Test signing key — must match the key used when both generating and validating
    private static final String TEST_SECRET = "testSecretKeyForJwtTestingPurposesOnlyLongEnough1234";
    private static final int TEST_EXPIRATION_MS = 3600000; // 1 hour

    @SuppressWarnings("null") // jwtUtils is guaranteed non-null by @InjectMocks at runtime
    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwtUtils, "jwtSecret", TEST_SECRET);
        ReflectionTestUtils.setField(jwtUtils, "jwtExpirationMs", TEST_EXPIRATION_MS);
    }

    @Test
    void generateJwtToken_shouldReturnValidToken() {
        // Happy path: valid authentication principal produces a non-empty compact JWT string
        var authentication = mock(Authentication.class);
        var userPrincipal = new UserDetailsImpl(1L, "testuser", "password", "Test", "User", List.of());
        when(authentication.getPrincipal()).thenReturn(userPrincipal);

        var token = jwtUtils.generateJwtToken(authentication);

        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void getUsernameFromJwtToken_shouldReturnUsername() {
        // Happy path: username stored as subject claim is extracted correctly
        String token = Jwts.builder()
                .setSubject("testuser")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + TEST_EXPIRATION_MS))
                .signWith(SignatureAlgorithm.HS512, TEST_SECRET)
                .compact();

        assertEquals("testuser", jwtUtils.getUsernameFromJwtToken(token));
    }

    @Test
    void validateJwtToken_shouldReturnTrueForValidToken() {
        // Happy path: freshly generated token with correct signature passes validation
        var authentication = mock(Authentication.class);
        var userPrincipal = new UserDetailsImpl(1L, "testuser", "password", "Test", "User", List.of());
        when(authentication.getPrincipal()).thenReturn(userPrincipal);
        var token = jwtUtils.generateJwtToken(authentication);

        assertTrue(jwtUtils.validateJwtToken(token));
    }

    @Test
    void validateJwtToken_shouldReturnFalseForExpiredToken() {
        // EP (invalid): token with expiration in the past triggers ExpiredJwtException → false
        String expiredToken = Jwts.builder()
                .setSubject("testuser")
                .setIssuedAt(new Date(System.currentTimeMillis() - 2000))
                .setExpiration(new Date(System.currentTimeMillis() - 1000))
                .signWith(SignatureAlgorithm.HS512, TEST_SECRET)
                .compact();

        assertFalse(jwtUtils.validateJwtToken(expiredToken));
    }

    @Test
    void validateJwtToken_shouldReturnFalseForMalformedToken() {
        // EP (invalid): a non-JWT string triggers MalformedJwtException → false
        assertFalse(jwtUtils.validateJwtToken("this.is.not.a.valid.jwt.token"));
    }

    @Test
    void validateJwtToken_shouldReturnFalseForWrongSignature() {
        // EP (invalid): token signed with a different key triggers SignatureException → false
        String tokenWithWrongKey = Jwts.builder()
                .setSubject("testuser")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + TEST_EXPIRATION_MS))
                .signWith(SignatureAlgorithm.HS512, "differentSecretKeyForTestingWrongSignature12345678")
                .compact();

        assertFalse(jwtUtils.validateJwtToken(tokenWithWrongKey));
    }

    @Test
    void validateJwtToken_shouldReturnFalseForEmptyToken() {
        // BVA: empty string (zero-length boundary) has no claims —
        // triggers IllegalArgumentException in jjwt parser → false
        assertFalse(jwtUtils.validateJwtToken(""));
    }
}
