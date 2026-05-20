package com.memilogistics.shipmentservice.controller;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.CarrierCompanyResponse;
import com.memilogistics.shipmentservice.dto.CreateCarrierProfileRequest;
import com.memilogistics.shipmentservice.dto.UpdateCarrierProfileRequest;
import com.memilogistics.shipmentservice.mapper.ProfileMapper;
import com.memilogistics.shipmentservice.service.CarrierProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/carriers/profile")
@RequiredArgsConstructor
public class CarrierProfileController {
    private final CarrierProfileService carrierProfileService;
    private final ProfileMapper profileMapper;

    @GetMapping("/me")
    public ResponseEntity<CarrierCompanyResponse> getProfile(@CurrentUser CustomUserPrincipal user) {
        var profile = carrierProfileService.getCarrierProfile(user);
        return ResponseEntity.ok(profileMapper.toCarrierCompanyResponse(profile));
    }

    @PostMapping("/create")
    public ResponseEntity<CarrierCompanyResponse> createProfile(@CurrentUser CustomUserPrincipal user,
                                                                @Valid @RequestBody CreateCarrierProfileRequest request) {
        var profile = carrierProfileService.createCarrierCompanyProfile(user, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(profileMapper.toCarrierCompanyResponse(profile));
    }

    @PatchMapping("/update")
    public ResponseEntity<CarrierCompanyResponse> updateProfile(@CurrentUser CustomUserPrincipal user,
                                                                @Valid @RequestBody UpdateCarrierProfileRequest request) {
        var profile = carrierProfileService.updateCarrierCompanyProfile(user, request);
        return ResponseEntity.ok(profileMapper.toCarrierCompanyResponse(profile));
    }
}
