package com.memilogistics.authservice.controller;

import com.memilogistics.authservice.dto.*;
import com.memilogistics.authservice.enums.Role;
import com.memilogistics.authservice.service.AuthService;
import com.memilogistics.authservice.service.PasswordResetService;
import jakarta.servlet.http.HttpServletRequest;
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

        //helper methods for creating cookies
        ResponseCookie accessCookie = createAccessCookie(response.getAccessToken());
        ResponseCookie refreshCookie = createRefreshCookie(response.getRefreshToken());

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
    public ResponseEntity<Void> refreshToken(@CookieValue("refreshToken") String refreshToken,
                                             HttpServletResponse httpResponse) {

        var authResponse = authService.refreshTokens(refreshToken);

        //helper methods for creating cookies
        ResponseCookie accessCookie = createAccessCookie(authResponse.getAccessToken());
        ResponseCookie refreshCookie = createRefreshCookie(authResponse.getRefreshToken());


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

    @PostMapping("/auth/logout")
    public ResponseEntity<Void> logout(@CookieValue(value = "refreshToken", required = false) String refreshToken,
                                       HttpServletResponse httpResponse) {

        if(refreshToken != null) {
            authService.logout(refreshToken);
        }
        ResponseCookie accessCookie = ResponseCookie.from(
                        "accessToken",
                        ""
                )
                .path("/")
                .maxAge(0)
                .build();

        ResponseCookie refreshCookie =
                ResponseCookie.from(
                                "refreshToken",
                                ""
                        )
                        .path("/auth/refresh")
                        .maxAge(0)
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

    private ResponseCookie createAccessCookie(String accessToken) {
        return ResponseCookie.from("accessToken", accessToken)
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(Duration.ofMinutes(15))
                .sameSite("Strict")
                .build();
    }
    private ResponseCookie createRefreshCookie(String refreshToken) {
        return ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(false)
                .path("/api/auth/refresh")
                .maxAge(Duration.ofDays(7))
                .sameSite("Strict")
                .build();
    }

}
