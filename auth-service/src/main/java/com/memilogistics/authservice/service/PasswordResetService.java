package com.memilogistics.authservice.service;

import com.memilogistics.authservice.dto.ForgotPasswordRequest;
import com.memilogistics.authservice.dto.ResetPasswordRequest;
import com.memilogistics.authservice.entity.PasswordResetToken;
import com.memilogistics.authservice.entity.User;
import com.memilogistics.authservice.repository.PasswordResetTokenRepository;
import com.memilogistics.authservice.repository.RefreshTokenRepository;
import com.memilogistics.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PasswordResetService {
    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

//    @Value("${application.security.password-reset-expiration}")
    private long resetTokenExpirationMs = 3600000;

//    @Value("${application.security.password-reset-url}")
    private String resetBaseUrl = "http://localhost:3000/reset-password";

    @Transactional
    public void requestReset(ForgotPasswordRequest request) {
        Optional<User> userOptional = userRepository.findByEmail(request.getEmail());
        if (userOptional.isEmpty()) {
            return; // Avoid email enumeration
        }

        User user = userOptional.get();
        passwordResetTokenRepository.deleteByUserId(user.getId());

        LocalDateTime expiry = LocalDateTime.now().plus(resetTokenExpirationMs, ChronoUnit.MILLIS);
        PasswordResetToken token = new PasswordResetToken(user, expiry);
        user.setPasswordResetToken(token);
        passwordResetTokenRepository.save(token);

        String resetLink = buildResetLink(token.getToken());
        emailService.sendPasswordResetEmail(user.getEmail(), resetLink);
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        PasswordResetToken token = passwordResetTokenRepository.findByToken(request.getToken())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid reset token"));

        if (!token.isUsable()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Reset token has expired or been used");
        }

        User user = token.getUser();
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        token.markUsed();

        passwordResetTokenRepository.save(token);
        userRepository.save(user);
        refreshTokenRepository.deleteByUserId(user.getId());
    }

    @Transactional
    public void cleanupExpiredTokens() {
        passwordResetTokenRepository.deleteByExpiryDateBefore(LocalDateTime.now());
    }

    private String buildResetLink(String token) {
        String base = resetBaseUrl.endsWith("/") ? resetBaseUrl.substring(0, resetBaseUrl.length() - 1) : resetBaseUrl;
        return base + "?token=" + token;
    }
}

//http://localhost:3000/reset-password?token=abc123def456ghi789jkl012mno345pq678rst901uvwx234yz567890ab12