package com.memilogistics.commonsecurity.jwt;

import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JwtAuthenticationFilterTest {

    private final JwtTokenProvider jwtTokenProvider = mock(JwtTokenProvider.class);

    private final JwtAuthenticationFilter filter =
            new JwtAuthenticationFilter(jwtTokenProvider);

    private final FilterChain filterChain = mock(FilterChain.class);


    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }


    @Test
    void doFilterInternal_shouldSkipWhenAccessTokenCookieMissing() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();


        filter.doFilter(request, response, filterChain);


        assertNull(
                SecurityContextHolder.getContext()
                        .getAuthentication()
        );

        verify(jwtTokenProvider)
                .isTokenValid(null);

        verify(filterChain)
                .doFilter(request, response);
    }


    @Test
    void doFilterInternal_shouldSkipWhenTokenInvalid() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();


        request.setCookies(
                new Cookie("accessToken", "invalid")
        );


        when(jwtTokenProvider.isTokenValid("invalid"))
                .thenReturn(false);


        filter.doFilter(request, response, filterChain);


        assertNull(
                SecurityContextHolder.getContext()
                        .getAuthentication()
        );


        verify(jwtTokenProvider)
                .isTokenValid("invalid");


        verify(filterChain)
                .doFilter(request, response);
    }


    @Test
    void doFilterInternal_shouldSetAuthoritiesFromTokenRoles() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();


        request.setCookies(
                new Cookie("accessToken", "valid")
        );


        TokenClaims claims = TokenClaims.builder()
                .userId("c69dfab3-9c87-43ca-a77c-a7be50e7a2b0")
                .authorities(
                        List.of(
                                "ROLE_ADMIN",
                                "PERMISSION_CREATE_LOAD"
                        )
                )
                .build();


        when(jwtTokenProvider.isTokenValid("valid"))
                .thenReturn(true);


        when(jwtTokenProvider.extractTokenClaims("valid"))
                .thenReturn(claims);



        filter.doFilter(request, response, filterChain);



        UsernamePasswordAuthenticationToken authentication =
                (UsernamePasswordAuthenticationToken)
                        SecurityContextHolder.getContext()
                                .getAuthentication();



        assertNotNull(authentication);



        CustomUserPrincipal principal =
                (CustomUserPrincipal)
                        authentication.getPrincipal();



        assertNotNull(principal);


        assertEquals(
                "c69dfab3-9c87-43ca-a77c-a7be50e7a2b0",
                principal.getId()
        );


        assertEquals(
                List.of(
                        "ROLE_ADMIN",
                        "PERMISSION_CREATE_LOAD"
                ),
                principal.getAuthorities()
        );


        assertEquals(
                List.of(
                        "ROLE_ADMIN",
                        "PERMISSION_CREATE_LOAD"
                ),
                authentication.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList()
        );


        verify(jwtTokenProvider)
                .isTokenValid("valid");


        verify(jwtTokenProvider)
                .extractTokenClaims("valid");


        verify(filterChain)
                .doFilter(request, response);
    }
}