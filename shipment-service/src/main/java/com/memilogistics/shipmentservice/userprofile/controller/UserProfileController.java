package com.memilogistics.shipmentservice.userprofile.controller;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.userprofile.dto.CreateUserProfileRequest;
import com.memilogistics.shipmentservice.userprofile.dto.UserProfileResponse;
import com.memilogistics.shipmentservice.userprofile.dto.UpdateUserProfileRequest;
import com.memilogistics.shipmentservice.userprofile.service.UserProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user/profile")
@RequiredArgsConstructor
public class UserProfileController {
    private final UserProfileService userProfileService;

    @GetMapping("/me")
    public ResponseEntity<UserProfileResponse> getProfile(@CurrentUser CustomUserPrincipal user) {
        var profile = userProfileService.getUserProfile(user);
        return ResponseEntity.ok(profile);
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserProfileResponse> getProfileById(@PathVariable Long id) {
        return ResponseEntity.ok(userProfileService.getUserProfile(id));
    }

    @PostMapping("create")
    public ResponseEntity<UserProfileResponse> createProfile(@CurrentUser CustomUserPrincipal user,
                                                             @Valid @RequestBody CreateUserProfileRequest request) {
        var profile = userProfileService.createUserProfile(user, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(profile);
    }

    @PatchMapping("update")
    public ResponseEntity<UserProfileResponse> updateProfile(@CurrentUser CustomUserPrincipal user,
                                                             @Valid @RequestBody UpdateUserProfileRequest request) {
        var profile = userProfileService.updateUserProfile(user, request);
        return ResponseEntity.ok(profile);
    }
}
