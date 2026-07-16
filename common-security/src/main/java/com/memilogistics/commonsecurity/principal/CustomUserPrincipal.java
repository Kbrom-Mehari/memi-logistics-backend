package com.memilogistics.commonsecurity.principal;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class CustomUserPrincipal {
    private String id;
    private String email;
    private List<String> authorities;
}
