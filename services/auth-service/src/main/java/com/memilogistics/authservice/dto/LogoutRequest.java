package com.memilogistics.authservice.dto;

import lombok.Data;

@Data
public class LogoutRequest {
    private String refreshToken;
}
