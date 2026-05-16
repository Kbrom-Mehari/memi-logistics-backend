package com.memilogistics.commonsecurity.handler;

import com.memilogistics.commonsecurity.exception.JwtAuthenticationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class SecurityExceptionHandler {

    @ExceptionHandler(JwtAuthenticationException.class)
    public ResponseEntity<String> handleJwtAuthenticationException(
            JwtAuthenticationException ex
    ) {

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(ex.getMessage());
    }
}
