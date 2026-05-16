package com.memilogistics.commonsecurity.jwt;

import com.memilogistics.commonsecurity.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

@Component
public class JwtTokenProvider {

    private final String jwtSecret;

    public JwtTokenProvider(JwtProperties properties) {
        this.jwtSecret = properties.getSecretKey();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public List<String> extractRoles(String token) {
        return extractClaim(token, claims -> claims.get("roles", List.class));
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    public TokenClaims extractTokenClaims(String token) {
        return TokenClaims.builder()
                .username(extractUsername(token))
                .roles(extractRoles(token))
                .build();
    }

    public boolean isTokenValid(String token) {
        try{
            return !isTokenExpired(token);
        }
        catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(Date.from(Instant.now()));
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
