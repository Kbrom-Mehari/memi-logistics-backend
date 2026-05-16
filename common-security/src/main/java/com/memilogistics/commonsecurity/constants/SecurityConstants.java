package com.memilogistics.commonsecurity.constants;

public final class SecurityConstants {
    // Prevent instantiation since this is a utility class
    private SecurityConstants() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String ROLES_CLAIM = "roles";

    // You can add global public paths here if all services need to ignore them
    public static final String[] GLOBAL_PUBLIC_URLS = {
            "/api/auth/**",
            "/error",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html"
    };
}

