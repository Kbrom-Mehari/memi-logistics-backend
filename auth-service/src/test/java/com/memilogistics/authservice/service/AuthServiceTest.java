package com.memilogistics.authservice.service;

import com.memilogistics.authservice.dto.AuthResponse;
import com.memilogistics.authservice.dto.LoginRequest;
import com.memilogistics.authservice.dto.RegisterRequest;
import com.memilogistics.authservice.entity.RefreshToken;
import com.memilogistics.authservice.entity.User;
import com.memilogistics.authservice.enums.Permissions;
import com.memilogistics.authservice.enums.Role;
import com.memilogistics.authservice.repository.RefreshTokenRepository;
import com.memilogistics.authservice.repository.UserRepository;
import com.memilogistics.authservice.security.CustomUserDetails;
import com.memilogistics.authservice.security.JwtService;
import com.memilogistics.authservice.util.RefreshTokenUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private AuthenticationManager authenticationManager;
    @Mock private JwtService jwtService;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private UserRepository userRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private RefreshTokenUtil refreshTokenUtil;

    @InjectMocks
    private AuthService authService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "REFRESH_TOKEN_EXPIRATION", 5_000L);
    }

    @Test
    void register_shouldEncodePasswordAndSaveUser() {
        RegisterRequest request = new RegisterRequest();
        request.setEmail("admin@memi.com");
        request.setPassword("plain-password");

        when(passwordEncoder.encode("plain-password")).thenReturn("hashed-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        authService.register(request);

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());

        User saved = captor.getValue();
        assertNotNull(saved.getId());
        assertEquals("admin@memi.com", saved.getEmail());
        assertEquals("hashed-password", saved.getPassword());
        assertEquals(Set.of(Role.USER), saved.getRoles());
        assertEquals(Set.of(Permissions.CREATE_LOAD), saved.getPermissions());
        assertNotNull(saved.getCreatedAt());
    }

    @Test
    void login_shouldReturnTokensAndPersistRefreshToken() {
        LoginRequest request = new LoginRequest();
        request.setEmail("admin@memi.com");
        request.setPassword("plain-password");

        Authentication authentication = mock(Authentication.class);
        CustomUserDetails userDetails = mock(CustomUserDetails.class);
        User user = User.builder()
                .id("user-id")
                .email("admin@memi.com")
                .password("hashed-password")
                .roles(Set.of(Role.USER))
                .permissions(Set.of(Permissions.CREATE_LOAD))
                .createdAt(LocalDateTime.now())
                .build();
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getId()).thenReturn("user-id");
        when(jwtService.generateToken(userDetails)).thenReturn("access-token");
        when(userRepository.findById("user-id")).thenReturn(Optional.of(user));
        when(refreshTokenUtil.generateRawToken()).thenReturn("raw-refresh-token");
        when(refreshTokenUtil.hash("raw-refresh-token")).thenReturn("hashed-refresh-token");
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AuthResponse response = authService.login(request);

        assertEquals("access-token", response.getAccessToken());
        assertEquals("raw-refresh-token", response.getRefreshToken());

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());

        RefreshToken saved = captor.getValue();
        assertEquals("hashed-refresh-token", saved.getHashedToken());
        assertEquals(user, saved.getUser());
        assertFalse(saved.isRevoked());
        assertTrue(saved.getExpiresAt().isAfter(saved.getCreatedAt()));
    }
    @Test
    void logout_shouldRevokeStoredRefreshToken() {
        RefreshToken stored = new RefreshToken();
        stored.setHashedToken("hashed-token");
        stored.setUser(User.builder().id("user-id").build());
        stored.setCreatedAt(LocalDateTime.now());
        stored.setExpiresAt(LocalDateTime.now().plusMinutes(10));
        stored.setRevoked(false);

        when(refreshTokenUtil.hash("raw-token")).thenReturn("hashed-token");
        when(refreshTokenRepository.findByHashedToken("hashed-token")).thenReturn(Optional.of(stored));

        authService.logout("raw-token");

        assertTrue(stored.isRevoked());
        verify(refreshTokenRepository).save(stored);
    }
    @Test
    void refreshTokens_shouldRotateTokens() {
        User user = User.builder()
                .id("user-id")
                .email("admin@memi.com")
                .password("hashed-password")
                .roles(Set.of(Role.USER))
                .permissions(Set.of(Permissions.CREATE_LOAD))
                .createdAt(LocalDateTime.now())
                .build();

        RefreshToken stored = new RefreshToken();
        stored.setHashedToken("hashed-old");
        stored.setUser(user);
        stored.setCreatedAt(LocalDateTime.now());
        stored.setExpiresAt(LocalDateTime.now().plusMinutes(10));
        stored.setRevoked(false);

        when(refreshTokenUtil.hash("old-refresh-token")).thenReturn("hashed-old");
        when(refreshTokenRepository.findByHashedToken("hashed-old")).thenReturn(Optional.of(stored));
        when(jwtService.generateToken(any(CustomUserDetails.class))).thenReturn("new-access-token");
        when(refreshTokenUtil.generateRawToken()).thenReturn("new-refresh-token");
        when(refreshTokenUtil.hash("new-refresh-token")).thenReturn("hashed-new");
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));


        AuthResponse response = authService.refreshTokens("old-refresh-token");

        assertEquals("new-access-token", response.getAccessToken());
        assertEquals("new-refresh-token", response.getRefreshToken());

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository, times(2)).save(captor.capture());

        List<RefreshToken> saved = captor.getAllValues();
        assertEquals(2, saved.size());
        assertTrue(saved.get(0).isRevoked());
        assertEquals("hashed-new", saved.get(1).getHashedToken());
        assertEquals(user, saved.get(1).getUser());
        assertFalse(saved.get(1).isRevoked());
        assertTrue(saved.get(1).getExpiresAt().isAfter(saved.get(1).getCreatedAt()));
    }
}