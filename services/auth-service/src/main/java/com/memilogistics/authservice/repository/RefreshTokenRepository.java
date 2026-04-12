package com.memilogistics.authservice.repository;

import com.memilogistics.authservice.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
     Optional<RefreshToken> findByUserId(String userId);
     Optional<RefreshToken> findByHashedToken(String hashedToken);
     void deleteByUserId(String userId);
}
