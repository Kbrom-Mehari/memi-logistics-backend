package com.memilogistics.authservice.security;

import com.memilogistics.authservice.config.JwtProperties;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    private JwtService jwtService;
    private UserDetails userDetails;

    @Mock
    private UserDetailsService userDetailsService;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties();
        properties.setSecretKey(base64Secret());
        properties.setExpiration(60_000L);

        jwtService = new JwtService(properties);
        userDetails = User.withUsername("admin@memi.com")
                .password("encoded-password")
                .authorities("ROLE_ADMIN")
                .build();
    }

    @Test
    void generateToken_ShouldCreateTokenAndExtractUsername() {
        String token = jwtService.generateToken(userDetails);

        assertNotNull(token);
        assertEquals("admin@memi.com", jwtService.extractUsername(token));
    }

    @Test
    void generateToken_WithExtraClaims_ShouldExposeClaimValues() {
        String token = jwtService.generateToken(Map.of("tenant", "memi"), userDetails);

        String tenant = jwtService.extractClaim(token, claims -> claims.get("tenant", String.class));

        assertEquals("memi", tenant);
    }

    @Test
    void isTokenValid_ShouldReturnTrueForMatchingUser() {
        String token = jwtService.generateToken(userDetails);

        assertTrue(jwtService.isTokenValid(token, userDetails));
    }

    @Test
    void isTokenValid_ShouldReturnFalseForDifferentUser() {
        String token = jwtService.generateToken(userDetails);
        UserDetails differentUser = User.withUsername("other@memi.com")
                .password("encoded-password")
                .authorities("ROLE_ADMIN")
                .build();

        assertFalse(jwtService.isTokenValid(token, differentUser));
    }

    @Test
    void extractUsername_ShouldThrowForMalformedToken() {
        assertThrows(JwtException.class, () -> jwtService.extractUsername("not-a-jwt"));
    }

    @Test
    void isTokenValid_ShouldThrowWhenTokenIsExpired() {
        JwtProperties expiredProperties = new JwtProperties();
        expiredProperties.setSecretKey(base64Secret());
        expiredProperties.setExpiration(-1L);

        JwtService expiredJwtService = new JwtService(expiredProperties);
        String expiredToken = expiredJwtService.generateToken(userDetails);

        assertThrows(ExpiredJwtException.class, () -> expiredJwtService.isTokenValid(expiredToken, userDetails));
    }

    @Test
    void isTokenValid_ShouldWorkWithUserLoadedFromUserDetailsService() {
        String token = jwtService.generateToken(userDetails);
        when(userDetailsService.loadUserByUsername("admin@memi.com")).thenReturn(userDetails);

        UserDetails loadedUser = userDetailsService.loadUserByUsername(jwtService.extractUsername(token));

        assertTrue(jwtService.isTokenValid(token, loadedUser));
        verify(userDetailsService).loadUserByUsername("admin@memi.com");
    }

    private String base64Secret() {
        // 32-byte key (256-bit) for HS256 compatibility.
        return Base64.getEncoder().encodeToString("01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8));
    }
}
