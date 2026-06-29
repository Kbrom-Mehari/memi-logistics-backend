package com.memilogistics.commonsecurity.jwt;

import com.memilogistics.commonsecurity.constants.SecurityConstants;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
            ) throws ServletException, IOException {

        String token = null;
        Cookie[] cookies = request.getCookies();
        if(cookies != null) {
            for(Cookie cookie : cookies) {
                if(cookie.getName().equals("accessToken")){
                    token = cookie.getValue();
                    break;
                }
            }
        }

        if(!jwtTokenProvider.isTokenValid(token)){
            filterChain.doFilter(request, response);
            return;
        }
        TokenClaims claims = jwtTokenProvider.extractTokenClaims(token);

        //Build authenticated principal.
        CustomUserPrincipal principal =
                new CustomUserPrincipal(
                        claims.getUsername(),
                        claims.getRoles()
                );

        //Convert roles to Spring Security authorities.
        List<SimpleGrantedAuthority> authorities = claims.getRoles().stream()
                .map(role -> {
                    String authority = role.startsWith("ROLE_") ? role : "ROLE_" + role;
                    return new SimpleGrantedAuthority(authority);
                })
                .toList();

        //Create authentication object with principal and authorities.
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        principal,
                        null,
                        authorities
                );

        //Set details from request (like IP, session ID) to authentication object.
        authentication.setDetails(
                new WebAuthenticationDetailsSource()
                        .buildDetails(request)
        );

        //Store authentication into SecurityContext.
        SecurityContextHolder
                .getContext()
                .setAuthentication(authentication);

        //Continue filter chain.
        filterChain.doFilter(request, response);
    }

}
