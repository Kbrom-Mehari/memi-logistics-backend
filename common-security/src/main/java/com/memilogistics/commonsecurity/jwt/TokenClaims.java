package com.memilogistics.commonsecurity.jwt;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Collection;

@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class TokenClaims {
    private String username;
    private Collection<String> roles;
}
