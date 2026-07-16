package com.memilogistics.authservice.security;

import com.memilogistics.authservice.entity.User;
import com.memilogistics.authservice.enums.Permissions;
import com.memilogistics.authservice.enums.Role;
import com.memilogistics.commonsecurity.config.JwtProperties;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.authority.SimpleGrantedAuthority;


import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    private JwtService jwtService;
    private CustomUserDetails userDetails;
    private User user ;

    @Mock
    private CustomUserDetailsService userDetailsService;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties();
        properties.setSecretKey(base64Secret());
        properties.setExpiration(60_000L);
        user = User.builder().id("721a3648-5249-43c2-ad62-cd73e89fb2bb")
                .email("admin@example.com")
                .roles(Set.of(Role.ADMIN))
                .permissions(Set.of(Permissions.CREATE_LOAD))
                .build();
        jwtService = new JwtService(properties);
        userDetails = new CustomUserDetails(user);
    }

    @Test
    void generateToken_ShouldCreateTokenAndExtractUserId() {
        String token = jwtService.generateToken(userDetails);

        assertNotNull(token);
        assertEquals("721a3648-5249-43c2-ad62-cd73e89fb2bb", jwtService.extractUserId(token));
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
        CustomUserDetails differentUser = new CustomUserDetails(User.builder().id("other-id")
                .email("admin@example.com")
                .password("encoded-password")
                .roles(Set.of(Role.USER))
                .permissions(Set.of(Permissions.CREATE_LOAD))
                .build());

        assertFalse(jwtService.isTokenValid(token, differentUser));
    }

    @Test
    void extractUserId_ShouldThrowForMalformedToken() {
        assertThrows(JwtException.class, () -> jwtService.extractUserId("not-a-jwt"));
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
        when(userDetailsService.loadUserByUserId("721a3648-5249-43c2-ad62-cd73e89fb2bb")).thenReturn(userDetails);

        CustomUserDetails loadedUser = userDetailsService.loadUserByUserId(jwtService.extractUserId(token));

        assertTrue(jwtService.isTokenValid(token, loadedUser));
        verify(userDetailsService).loadUserByUserId("721a3648-5249-43c2-ad62-cd73e89fb2bb");
    }

    private String base64Secret() {
        // 32-byte key (256-bit) for HS256 compatibility.
        return Base64.getEncoder().encodeToString("01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8));
    }
}
