package com.memilogistics.authservice.controller;

import com.memilogistics.authservice.dto.*;
import com.memilogistics.authservice.enums.Role;
import com.memilogistics.authservice.service.AuthService;
import com.memilogistics.authservice.service.PasswordResetService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.Response;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequestMapping("api")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final PasswordResetService passwordResetService;

    @PostMapping("/auth/login")
    public ResponseEntity<Void> login(@RequestBody @Valid LoginRequest loginRequest,
                                      HttpServletResponse httpResponse){
        var response =  authService.login(loginRequest);
        ResponseCookie accessCookie =
                ResponseCookie.from("accessToken", response.getAccessToken())
                        .httpOnly(true)
                        .secure(false)
                        .path("/")
                        .maxAge(Duration.ofMinutes(15))
                        .sameSite("Strict")
                        .build();
        ResponseCookie refreshCookie =
                ResponseCookie.from("refreshToken", response.getRefreshToken())
                        .httpOnly(true)
                        .secure(false)
                        .path("/")
                        .maxAge(Duration.ofDays(7))
                        .sameSite("Strict")
                        .build();
        httpResponse.addHeader(
                HttpHeaders.SET_COOKIE,
                accessCookie.toString()
        );

        httpResponse.addHeader(
                HttpHeaders.SET_COOKIE,
                refreshCookie.toString()
        );

        return ResponseEntity.ok().build();
    }

    @PostMapping("/auth/register")
    public ResponseEntity<Void> register(
            @RequestParam("role") String role,
            @RequestBody @Valid RegisterRequest registerRequest
    ){
        Role parsedRole;
        try {
            parsedRole = Role.valueOf(role.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid role. Allowed roles: shipper, carrier");
        }

        if (parsedRole == Role.ADMIN) {
            throw new IllegalArgumentException("ADMIN registration is not allowed");
        }

        authService.register(registerRequest, parsedRole);

        return ResponseEntity.ok().build();
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshRequest refreshRequest) {
        return ResponseEntity.ok(authService.refreshTokens(refreshRequest));
    }
    @PostMapping("/auth/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequest logoutRequest) {
        authService.logout(logoutRequest);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/auth/forgot-password")
    public ResponseEntity<Void> forgotPassword(@RequestBody @Valid ForgotPasswordRequest request) {
        passwordResetService.requestReset(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/auth/reset-password")
    public ResponseEntity<Void> resetPassword(@RequestBody @Valid ResetPasswordRequest request) {
        passwordResetService.resetPassword(request);
        return ResponseEntity.ok().build();
    }

}
