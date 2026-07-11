package com.memilogistics.authservice.dto;

import lombok.Builder;

import java.util.List;

@Builder
public class UserResponse {
    private String id;
    private String email;
    private List<String> authorities;
}
