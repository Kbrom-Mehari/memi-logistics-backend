package com.memilogistics.commonsecurity.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import java.io.IOException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthenticationEntryPointTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JwtAuthenticationEntryPoint entryPoint = new JwtAuthenticationEntryPoint(objectMapper);

    @Test
    void shouldReturn401WhenUnauthorized() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/secure");
        MockHttpServletResponse response = new MockHttpServletResponse();

        BadCredentialsException exception = new BadCredentialsException("Bad token");

        entryPoint.commence(request, response, exception);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).isEqualTo("application/json");

        Map<String, Object> body = objectMapper.readValue(response.getContentAsByteArray(), Map.class);
        assertThat(body.get("error")).isEqualTo("Unauthorized");
        assertThat(body.get("message")).isEqualTo("Bad token");
        assertThat(body.get("path")).isEqualTo("/api/secure");
        assertThat(body.containsKey("timestamp")).isTrue();
    }
}
