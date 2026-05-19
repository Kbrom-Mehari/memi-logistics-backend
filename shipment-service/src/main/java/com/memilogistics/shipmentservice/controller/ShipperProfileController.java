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
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/shippers/profile")
@RequiredArgsConstructor
public class ShipperProfileController {
    private final ShipperProfileService shipperProfileService;
    private final ShipmentMapper shipmentMapper;

    @PostMapping
    public ResponseEntity<ShipperProfileResponse> createProfile(@CurrentUser CustomUserPrincipal user,
                                                                @Valid @RequestBody CreateShipperProfileRequest request) {
        var profile = shipperProfileService.createShipperProfile(user, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(shipmentMapper.toShipperProfileResponse(profile));
    }

    @PatchMapping
    public ResponseEntity<ShipperProfileResponse> updateProfile(@CurrentUser CustomUserPrincipal user,
                                                                @Valid @RequestBody UpdateShipperProfileRequest request) {
        var profile = shipperProfileService.updateShipperProfile(user, request);
        return ResponseEntity.ok(shipmentMapper.toShipperProfileResponse(profile));
    }
}
