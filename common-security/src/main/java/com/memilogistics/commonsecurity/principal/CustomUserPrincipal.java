package com.memilogistics.commonsecurity.principal;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Collection;

@Getter
@AllArgsConstructor
public class CustomUserPrincipal {
    private String username;
    private Collection<String> roles;
}
