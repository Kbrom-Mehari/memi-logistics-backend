package com.memilogistics.commonsecurity.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;

import java.io.IOException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAccessDeniedHandlerTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JwtAccessDeniedHandler handler = new JwtAccessDeniedHandler(objectMapper);


    @Test
    void shouldReturn403WhenAccessDenied() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/test");
        MockHttpServletResponse response = new MockHttpServletResponse();

        AccessDeniedException exception = new AccessDeniedException("Not allowed here");

        handler.handle(request, response, exception);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentType()).isEqualTo("application/json");

        Map<String, Object> body = objectMapper.readValue(response.getContentAsByteArray(), Map.class);
        assertThat(body.get("status")).isEqualTo(403);
        assertThat(body.get("error")).isEqualTo("Forbidden");
        assertThat(body.get("message")).isEqualTo("Not allowed here");
        assertThat(body.get("path")).isEqualTo("/api/test");
        assertThat(body.containsKey("timestamp")).isTrue();
    }
}
