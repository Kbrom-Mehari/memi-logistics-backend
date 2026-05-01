package com.memilogistics.authservice.service;

import com.memilogistics.authservice.dto.AuthResponse;
import com.memilogistics.authservice.dto.LoginRequest;
import com.memilogistics.authservice.dto.RegisterRequest;
import com.memilogistics.authservice.entity.User;
import com.memilogistics.authservice.enums.Role;
import com.memilogistics.authservice.repository.UserRepository;
import com.memilogistics.authservice.security.JwtService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)  //Enable mockito annotations like @Mock, @InjectMocks, etc.
public class AuthServiceTest {
    @Mock
    private UserRepository userRepository;
    @Mock
    AuthenticationManager authenticationManager;
    @Mock
    private JwtService jwtService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @InjectMocks    // inject those mock to this class(which is being tested)
    private AuthService authService;

    @Test
    void register_ShouldEncodePasswordAndSaveUser() {
        //Arrange
        RegisterRequest request = new RegisterRequest();
        request.setEmail("admin@memi.com");
        request.setPassword("plain-password");

        //Mocking the behavior of passwordEncoder to return a hashed password when encode is called with "plain-password"
        when(passwordEncoder.encode("plain-password")).thenReturn("hashed-password");

        //Act
        authService.register(request);
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

        //Verify that userRepository.save() was called and capture the User object passed to it
        verify(userRepository).save(userCaptor.capture());

        //Get the captured User object
        User savedUser = userCaptor.getValue();

        assertNotNull(savedUser.getId());
        assertFalse(savedUser.getId().isBlank());
        assertEquals("admin@memi.com", savedUser.getEmail());
        assertEquals("hashed-password", savedUser.getPassword());
        assertEquals(Role.ADMIN, savedUser.getRole());
        assertNotNull(savedUser.getCreatedAt());
        verify(passwordEncoder).encode("plain-password");
    }
    @Test
    void login_shouldAuthenticateAndGenerateTokenFromUserDetails(){

        //ARRANGE

        LoginRequest request = new LoginRequest();
        request.setEmail("admin@memi.com");
        request.setPassword("plain-password");

        // mock/fake authenticated user
        UserDetails userDetails = User.builder()
                .id("user-id")
                .email("admin@memi.com")
                .password("hashed-password")
                .role(Role.ADMIN)
                .createdAt(LocalDateTime.now())
                .build();
        //mock spring security response
        Authentication authentication = mock(Authentication.class);

        //when login happens, return authentication object
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);

        //when extracting user, return our fake user
        when(authentication.getPrincipal()).thenReturn(userDetails);
        //when we generate token for our fake user, return fake token jwt-token
        when(jwtService.generateToken(userDetails)).thenReturn("jwt-token");

        //ACT
        AuthResponse response = authService.login(request);

        //ASSERT
        assertNotNull(response);
        assertEquals("jwt-token", response.getToken());

        //used to capture what was passed to authenticate()
        ArgumentCaptor<UsernamePasswordAuthenticationToken> tokenCaptor
                = ArgumentCaptor.forClass(UsernamePasswordAuthenticationToken.class);
        verify(authenticationManager).authenticate(tokenCaptor.capture());
        UsernamePasswordAuthenticationToken authenticationToken = tokenCaptor.getValue();

        assertEquals("admin@memi.com", authenticationToken.getPrincipal());
        assertEquals("plain-password", authenticationToken.getCredentials());

        //verify token was generated
        verify(jwtService).generateToken(userDetails);
    }

    @Test
    void login_shouldPropagateAuthenticationFailure(){
        //ARRANGE
        LoginRequest request = new LoginRequest();
        request.setEmail("admin@memi.com");
        request.setPassword("wrong-password");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Bad Credentials"));
        assertThrows(BadCredentialsException.class, ()-> authService.login(request));
        verify(jwtService, never()).generateToken(any(UserDetails.class));
    }

    @Test
    void login_ShouldPropagateJwtGenerationFailure_AfterSuccessfulAuthentication(){
        LoginRequest request = new LoginRequest();
        request.setEmail("admin@memi.com");
        request.setPassword("plain-password");

        UserDetails userDetails = User.builder()
                .id("user-id")
                .email("admin@memi.com")
                .password("hashed-password")
                .role(Role.ADMIN)
                .createdAt(LocalDateTime.now())
                .build();

        Authentication authentication = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(jwtService.generateToken(userDetails)).thenThrow(new RuntimeException("Jwt generation failed"));
        assertThrows(RuntimeException.class, () -> authService.login(request));
    }
}