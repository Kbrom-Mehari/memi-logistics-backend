package com.memilogistics.authservice.config;

import com.memilogistics.authservice.entity.User;
import com.memilogistics.authservice.enums.Role;
import com.memilogistics.authservice.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class AdminInitializer implements CommandLineRunner {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${application.security.initial-admin.email}")
    private String adminEmail;
    @Value("${application.security.initial-admin.password}")
    private String adminPassword;

    @Override
    @Transactional
    public void run(String... args) throws Exception {
        boolean adminExists = userRepository.existsByEmail(adminEmail) ||
                userRepository.existsByRole(Role.ADMIN);

        if(!adminExists) {
            System.out.println("No administrative user found. Seeding initial admin...");
            User user = User.builder()
                    .id(UUID.randomUUID().toString())
                    .email(adminEmail)
                    .role(Role.ADMIN)
                    .password(passwordEncoder.encode(adminPassword))
                    .createdAt(LocalDateTime.now())
                    .build();
            userRepository.save(user);
            System.out.println("Initial admin account successfully created with email: " + adminEmail);

        }
        else
            System.out.println("Administrative account already exists. Skipping database seeding.");

    }
}
