package com.memilogistics.authservice.service;

import com.memilogistics.authservice.dto.ForgotPasswordRequest;
import com.memilogistics.authservice.dto.ResetPasswordRequest;
import com.memilogistics.authservice.entity.PasswordResetToken;
import com.memilogistics.authservice.entity.User;
import com.memilogistics.authservice.repository.PasswordResetTokenRepository;
import com.memilogistics.authservice.repository.RefreshTokenRepository;
import com.memilogistics.authservice.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private PasswordResetService passwordResetService;

    private User user;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id("user-1")
                .email("user@memi.com")
                .password("old-hash")
                .build();

        ReflectionTestUtils.setField(passwordResetService, "resetTokenExpirationMs", 3600000L);
        ReflectionTestUtils.setField(passwordResetService, "resetBaseUrl", "https://app.memi.com/reset-password");
    }

    @Test
    void requestReset_ShouldNoop_WhenUserNotFound() {
        ForgotPasswordRequest request = new ForgotPasswordRequest();
        request.setEmail("missing@memi.com");

        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.empty());

        passwordResetService.requestReset(request);

        verify(userRepository).findByEmail(request.getEmail());
        verifyNoInteractions(passwordResetTokenRepository, emailService, refreshTokenRepository);
    }

    @Test
    void requestReset_ShouldCreateTokenAndSendEmail_WhenUserFound() {
        ForgotPasswordRequest request = new ForgotPasswordRequest();
        request.setEmail(user.getEmail());

        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordResetTokenRepository.save(any(PasswordResetToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        passwordResetService.requestReset(request);

        verify(passwordResetTokenRepository).deleteByUserId(user.getId());
        ArgumentCaptor<PasswordResetToken> tokenCaptor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(passwordResetTokenRepository).save(tokenCaptor.capture());

        PasswordResetToken savedToken = tokenCaptor.getValue();
        assertEquals(user, savedToken.getUser());
        assertFalse(savedToken.isExpired());
        assertFalse(savedToken.isUsed());

        ArgumentCaptor<String> linkCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendPasswordResetEmail(eq(user.getEmail()), linkCaptor.capture());
        assertEquals("https://app.memi.com/reset-password?token=" + savedToken.getToken(), linkCaptor.getValue());
    }

    @Test
    void resetPassword_ShouldThrow_WhenTokenMissing() {
        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("missing-token");
        request.setNewPassword("NewPass123");

        when(passwordResetTokenRepository.findByToken(request.getToken())).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> passwordResetService.resetPassword(request));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        verifyNoInteractions(refreshTokenRepository);
    }

    @Test
    void resetPassword_ShouldThrow_WhenTokenExpired() {
        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("expired-token");
        request.setNewPassword("NewPass123");

        PasswordResetToken token = new PasswordResetToken(user, LocalDateTime.now().minusMinutes(5));
        when(passwordResetTokenRepository.findByToken(request.getToken())).thenReturn(Optional.of(token));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> passwordResetService.resetPassword(request));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        verify(passwordResetTokenRepository, never()).save(any(PasswordResetToken.class));
        verify(userRepository, never()).save(any(User.class));
        verify(refreshTokenRepository, never()).deleteByUserId(anyString());
    }

    @Test
    void resetPassword_ShouldUpdatePasswordAndRevokeTokens_WhenValid() {
        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("valid-token");
        request.setNewPassword("NewPass123");

        PasswordResetToken token = new PasswordResetToken(user, LocalDateTime.now().plus(30, ChronoUnit.MINUTES));
        when(passwordResetTokenRepository.findByToken(request.getToken())).thenReturn(Optional.of(token));
        when(passwordEncoder.encode(request.getNewPassword())).thenReturn("new-hash");

        passwordResetService.resetPassword(request);

        assertEquals("new-hash", user.getPassword());
        assertTrue(token.isUsed());
        verify(passwordResetTokenRepository).save(token);
        verify(userRepository).save(user);
        verify(refreshTokenRepository).deleteByUserId(user.getId());
    }
}

