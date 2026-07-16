package com.memilogistics.commonsecurity.jwt;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class TokenClaims {
    private String userId;
    private String email;
    private List<String> authorities;
}
