package com.memilogistics.authservice.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(
        name = "password_reset_tokens",
        indexes = {
                @Index(name = "idx_password_reset_token_token", columnList = "token"),
                @Index(name = "idx_password_reset_token_user", columnList = "user_id"),
                @Index(name = "idx_password_reset_token_expiry", columnList = "expiry_date")
        }
)
@Getter
@Setter
public class PasswordResetToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String token;

    @OneToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    @Column(name = "expiry_date", nullable = false, updatable = false)
    private LocalDateTime expiryDate;

    @Column(nullable = false)
    private boolean used;

    protected PasswordResetToken() {
    }

    public PasswordResetToken(User user, LocalDateTime expiryDate) {
        this.user = user;
        this.expiryDate = expiryDate;
        this.token = generateToken();
        this.used = false;
    }

    @PrePersist
    void initializeDefaults() {
        if (token == null || token.isBlank()) {
            token = generateToken();
        }
        if (expiryDate == null) {
            expiryDate = LocalDateTime.now().plusHours(1);
        }
    }

    public static String generateToken() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    public boolean isExpired() {
        return expiryDate.isBefore(LocalDateTime.now());
    }

    public boolean isUsable() {
        return !used && !isExpired();
    }

    public void markUsed() {
        this.used = true;
    }

}
