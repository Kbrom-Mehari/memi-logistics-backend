package com.memilogistics.authservice.security;

import com.memilogistics.authservice.entity.User;
import com.memilogistics.commonsecurity.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class  JwtService {
	private final String jwtSecret;
	private final long jwtExpirationMs;

	public JwtService(JwtProperties properties) {
		this.jwtSecret = properties.getSecretKey();
		this.jwtExpirationMs = properties.getExpiration();
	}

	public String extractUserId(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}

	public String generateToken(CustomUserDetails user) {
		Map<String, Object> claims = Map.of("authorities" , user.getAuthorities()
				.stream()
				.map(GrantedAuthority::getAuthority)
				.toList(), "email", user.getUsername());
		return generateToken(claims, user);
	}

	public String generateToken(Map<String, Object> claims, CustomUserDetails user) {
		Instant now = Instant.now();
		Instant expiry = now.plusMillis(jwtExpirationMs);
		Date issuedAt = Date.from(now);
		Date expiryDate = Date.from(expiry);

		return Jwts.builder()
				.claims(claims)
				.subject(user.getId())
				.issuedAt(issuedAt)
				.issuer("logicare.com")
				.expiration(expiryDate)
				.signWith(getSigningKey())
				.compact();
	}

	public boolean isTokenValid(String token, CustomUserDetails user) {
		String id = extractUserId(token);
		return id.equals(user.getId()) && !isTokenExpired(token);
	}

	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(Date.from(Instant.now()));
	}

	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	private Claims extractAllClaims(String token) {
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
