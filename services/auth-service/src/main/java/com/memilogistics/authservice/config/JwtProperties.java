package com.memilogistics.authservice.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "application.security.jwt")
@Component
@Getter
@Setter
public class JwtProperties {
    private String secretKey;
    private long expiration;
}
