package com.memilogistics.authservice.service;

import com.memilogistics.authservice.dto.*;
import com.memilogistics.authservice.entity.RefreshToken;
import com.memilogistics.authservice.entity.User;
import com.memilogistics.authservice.enums.Permissions;
import com.memilogistics.authservice.enums.Role;
import com.memilogistics.authservice.repository.RefreshTokenRepository;
import com.memilogistics.authservice.repository.UserRepository;
import com.memilogistics.authservice.security.CustomUserDetails;
import com.memilogistics.authservice.security.JwtService;
import com.memilogistics.authservice.util.RefreshTokenUtil;
import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.Set;
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


    public void register(RegisterRequest registerRequest){
        userRepository.findByEmail(registerRequest.getEmail()).ifPresent(u -> {
            throw new IllegalArgumentException("Email already in use");
        });

        String hashedPassword = passwordEncoder.encode(registerRequest.getPassword());
        User user = User.builder()
                .id(UUID.randomUUID().toString())
                .email(registerRequest.getEmail())
                .password(hashedPassword)
                .roles(Set.of(Role.USER))
                .permissions(Set.of(Permissions.CREATE_LOAD))
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
        CustomUserDetails userDetails =(CustomUserDetails) authentication.getPrincipal();

        String accessToken = jwtService.generateToken(
                Objects.requireNonNull(userDetails, "User details cannot be null")
        );

        User user = userRepository.findById(userDetails.getId()).orElseThrow(
                ()-> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found")
        );

        String refreshToken = createRefreshToken(user);

        return new AuthResponse(accessToken, refreshToken);
    }
    public void logout(String refreshToken){
        String hashed =refreshTokenUtil.hash(refreshToken);
        RefreshToken stored = refreshTokenRepository.findByHashedToken(hashed)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid refresh token"));
        stored.setRevoked(true);
        refreshTokenRepository.save(stored);
    }

    public AuthResponse refreshTokens(String refreshToken){
        String hashed = refreshTokenUtil.hash(refreshToken);
        RefreshToken stored = refreshTokenRepository.findByHashedToken(hashed)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token"));
        if(stored.isRevoked()){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid refresh token");
        }
        if(stored.getExpiresAt().isBefore(LocalDateTime.now())){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Refresh token has expired");
        }

        User user = stored.getUser();

        stored.setRevoked(true);
        refreshTokenRepository.save(stored);

        String newAccessToken = jwtService.generateToken(new CustomUserDetails(user));
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

    public UserResponse getCurrentUser(@CurrentUser CustomUserPrincipal user){
        return UserResponse.builder().id(user.getId())
                .email(user.getEmail())
                .authorities(user.getAuthorities()).build();
    }
}
