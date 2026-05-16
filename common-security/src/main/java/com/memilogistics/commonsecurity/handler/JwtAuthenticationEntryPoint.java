package com.memilogistics.commonsecurity.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final ObjectMapper objectMapper;

    @Override
    public void commence(@NonNull HttpServletRequest request,
                         HttpServletResponse response,
                         @NonNull AuthenticationException authException
    ) throws IOException, ServletException {

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        Map<String, Object> body = new HashMap<>();

        body.put("timestamp", Instant.now().toString());
        body.put("message", authException.getMessage());
        body.put("error", "Unauthorized");
        body.put("path", request.getServletPath());

        objectMapper.writeValue(response.getOutputStream(), body);
    }

}
