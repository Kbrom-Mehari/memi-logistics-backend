package com.memilogistics.shipmentservice.controller;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.CarrierCompanyResponse;
import com.memilogistics.shipmentservice.dto.CreateCarrierProfileRequest;
import com.memilogistics.shipmentservice.dto.UpdateCarrierProfileRequest;
import com.memilogistics.shipmentservice.mapper.ShipmentMapper;
import com.memilogistics.shipmentservice.service.CarrierProfileService;
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
@RequestMapping("/api/carriers/profile")
@RequiredArgsConstructor
public class CarrierProfileController {
    private final CarrierProfileService carrierProfileService;
    private final ShipmentMapper shipmentMapper;

    @PostMapping
    public ResponseEntity<CarrierCompanyResponse> createProfile(@CurrentUser CustomUserPrincipal user,
                                                                @Valid @RequestBody CreateCarrierProfileRequest request) {
        var profile = carrierProfileService.createCarrierCompanyProfile(user, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(shipmentMapper.toCarrierCompanyResponse(profile));
    }

    @PatchMapping
    public ResponseEntity<CarrierCompanyResponse> updateProfile(@CurrentUser CustomUserPrincipal user,
                                                                @Valid @RequestBody UpdateCarrierProfileRequest request) {
        var profile = carrierProfileService.updateCarrierCompanyProfile(user, request);
        return ResponseEntity.ok(shipmentMapper.toCarrierCompanyResponse(profile));
    }
}
