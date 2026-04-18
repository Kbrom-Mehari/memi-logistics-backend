package com.memilogistics.authservice.security;

import com.memilogistics.authservice.config.JwtProperties;
import com.memilogistics.authservice.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
	private final String jwtSecret;
	private final long jwtExpirationMs;

	public JwtService(JwtProperties properties) {
		this.jwtSecret = properties.getSecretKey();
		this.jwtExpirationMs = properties.getExpiration();
	}

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}

	public String generateToken(UserDetails user) {
		return generateToken(new HashMap<>(), user);
	}

	public String generateToken(Map<String, Object> extraClaims, UserDetails user) {
		Instant now = Instant.now();
		Instant expiry = now.plusMillis(jwtExpirationMs);
		Date issuedAt = Date.from(now);
		Date expiryDate = Date.from(expiry);

		return Jwts.builder()
				.claims(extraClaims)
				.subject(user.getUsername())
				.issuedAt(issuedAt)
				.expiration(expiryDate)
				.signWith(getSigningKey())
				.compact();
	}

	public boolean isTokenValid(String token, UserDetails user) {
		String username = extractUsername(token);
		return username.equals(user.getUsername()) && !isTokenExpired(token);
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
