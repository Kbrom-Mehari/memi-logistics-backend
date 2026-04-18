package com.memilogistics.authservice.service;

import com.memilogistics.authservice.dto.*;
import com.memilogistics.authservice.entity.RefreshToken;
import com.memilogistics.authservice.entity.User;
import com.memilogistics.authservice.enums.Role;
import com.memilogistics.authservice.repository.RefreshTokenRepository;
import com.memilogistics.authservice.repository.UserRepository;
import com.memilogistics.authservice.security.JwtService;
import com.memilogistics.authservice.util.RefreshTokenUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenUtil refreshTokenUtil;

    @Value("${application.security.refresh-token-expiration}")
    private long REFRESH_TOKEN_EXPIRATION ;


    public void registerCarrier(RegisterRequest registerRequest){
        String hashedPassword = passwordEncoder.encode(registerRequest.getPassword());
        User user = User.builder()
                .id(UUID.randomUUID().toString())
                .email(registerRequest.getEmail())
                .password(hashedPassword)
                .role(Role.CARRIER)
                .createdAt(LocalDateTime.now()).build();
        userRepository.save(user);
    }

    public void registerShipper(RegisterRequest registerRequest){
        String hashedPassword = passwordEncoder.encode(registerRequest.getPassword());
        User user = User.builder()
                .id(UUID.randomUUID().toString())
                .email(registerRequest.getEmail())
                .password(hashedPassword)
                .role(Role.SHIPPER)
                .createdAt(LocalDateTime.now()).build();
        userRepository.save(user);
    }

    public AuthResponse login(LoginRequest loginRequest){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()
                )
        );
        UserDetails userDetails =(UserDetails) authentication.getPrincipal();

        String accessToken = jwtService.generateToken(userDetails);
        String refreshToken = createRefreshToken((User) userDetails);

        return new AuthResponse(accessToken, refreshToken);
    }
    public void logout(LogoutRequest logoutRequest){
        String hashed =refreshTokenUtil.hash(logoutRequest.getRefreshToken());
        RefreshToken stored = refreshTokenRepository.findByHashedToken(hashed)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        stored.setRevoked(true);
        refreshTokenRepository.save(stored);
    }

    public AuthResponse refreshTokens(RefreshRequest refreshRequest){
        String hashed = refreshTokenUtil.hash(refreshRequest.getRefreshToken());
        RefreshToken stored = refreshTokenRepository.findByHashedToken(hashed)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        if(stored.isRevoked()){
            throw new RuntimeException("Refresh token has been revoked");
        }
        if(stored.getExpiresAt().isBefore(LocalDateTime.now())){
            throw new RuntimeException("Refresh token has expired");
        }

        User user = stored.getUser();

        stored.setRevoked(true);
        refreshTokenRepository.save(stored);

        String newAccessToken = jwtService.generateToken(user);
        String newRefreshToken = createRefreshToken(user);

        return new AuthResponse(newAccessToken, newRefreshToken);
    }

    private String createRefreshToken(User user){
        String rawToken = refreshTokenUtil.generateRawToken();
        String hashed = refreshTokenUtil.hash(rawToken);
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setCreatedAt(LocalDateTime.now());
        refreshToken.setHashedToken(hashed);
        refreshToken.setUser(user);
        refreshToken.setRevoked(false);
        refreshToken.setExpiresAt(LocalDateTime.now().plus(REFRESH_TOKEN_EXPIRATION, ChronoUnit.MILLIS));

        refreshTokenRepository.save(refreshToken);
        return rawToken;
    }
}
