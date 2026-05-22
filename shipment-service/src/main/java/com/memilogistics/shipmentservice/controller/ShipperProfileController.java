package com.memilogistics.shipmentservice.controller;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.CreateShipperProfileRequest;
import com.memilogistics.shipmentservice.dto.ShipperProfileResponse;
import com.memilogistics.shipmentservice.dto.UpdateShipperProfileRequest;
import com.memilogistics.shipmentservice.mapper.ShipmentMapper;
import com.memilogistics.shipmentservice.service.ShipperProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/shippers/profile")
@RequiredArgsConstructor
public class ShipperProfileController {
    private final ShipperProfileService shipperProfileService;

    @GetMapping("/me")
    public ResponseEntity<ShipperProfileResponse> getProfile(@CurrentUser CustomUserPrincipal user) {
        var profile = shipperProfileService.getShipperProfile(user);
        return ResponseEntity.ok(profile);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ShipperProfileResponse> getProfileById(@PathVariable Long id) {
        return ResponseEntity.ok(shipperProfileService.getShipperProfile(id));
    }

    @PostMapping("create")
    public ResponseEntity<ShipperProfileResponse> createProfile(@CurrentUser CustomUserPrincipal user,
                                                                @Valid @RequestBody CreateShipperProfileRequest request) {
        var profile = shipperProfileService.createShipperProfile(user, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(profile);
    }

    @PatchMapping("update")
    public ResponseEntity<ShipperProfileResponse> updateProfile(@CurrentUser CustomUserPrincipal user,
                                                                @Valid @RequestBody UpdateShipperProfileRequest request) {
        var profile = shipperProfileService.updateShipperProfile(user, request);
        return ResponseEntity.ok(profile);
    }
}
