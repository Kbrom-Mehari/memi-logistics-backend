package com.memilogistics.authservice.controller;

import com.memilogistics.authservice.dto.*;
import com.memilogistics.authservice.enums.Role;
import com.memilogistics.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/auth/login")
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid LoginRequest loginRequest){
        return ResponseEntity.ok(authService.login(loginRequest));
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

        if (parsedRole == Role.SHIPPER) {
            authService.registerShipper(registerRequest);
        } else if (parsedRole == Role.CARRIER) {
            authService.registerCarrier(registerRequest);
        }

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

}
