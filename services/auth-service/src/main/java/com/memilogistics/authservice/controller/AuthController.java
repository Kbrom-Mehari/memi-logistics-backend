package com.memilogistics.authservice.controller;

import com.memilogistics.authservice.dto.AuthResponse;
import com.memilogistics.authservice.dto.LoginRequest;
import com.memilogistics.authservice.dto.RegisterRequest;
import com.memilogistics.authservice.entity.User;
import com.memilogistics.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest loginRequest){
        return authService.login(loginRequest);
    }
    @PostMapping("/register")
    public String register(@RequestBody RegisterRequest registerRequest){
        authService.register(registerRequest);
        return "User registered successfully";
    }
    @GetMapping("/getUser")
    public User getUser(@RequestBody RegisterRequest req){
        return authService.getUser(req.getEmail());
    }

}
