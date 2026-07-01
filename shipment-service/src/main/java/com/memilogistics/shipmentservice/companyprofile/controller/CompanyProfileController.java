package com.memilogistics.shipmentservice.companyprofile.controller;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.companyprofile.dto.CompanyProfileResponse;
import com.memilogistics.shipmentservice.companyprofile.dto.CreateCompanyProfileRequest;
import com.memilogistics.shipmentservice.shipment.dto.ShipmentResponse;
import com.memilogistics.shipmentservice.companyprofile.dto.UpdateCompanyProfileRequest;
import com.memilogistics.shipmentservice.companyprofile.service.CompanyProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/company")
@RequiredArgsConstructor
public class CompanyProfileController {
    private final CompanyProfileService companyProfileService;

    @GetMapping("/profile/my")
    public ResponseEntity<CompanyProfileResponse> getCompanyProfile(@CurrentUser CustomUserPrincipal user) {
        return ResponseEntity.ok(companyProfileService.getCompanyProfile(user));
    }

    @GetMapping("/profile/{id}")
    public ResponseEntity<CompanyProfileResponse> getCompanyProfile(@PathVariable("id") Long id) {
        return ResponseEntity.ok(companyProfileService.getCompanyProfile(id));
    }

    @PostMapping("/profile/create")
    public ResponseEntity<CompanyProfileResponse> createProfile(@CurrentUser CustomUserPrincipal user,
                                                                @Valid @RequestBody CreateCompanyProfileRequest request) {
        var profile = companyProfileService.createCompanyProfile(user, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(profile);
    }

    @PatchMapping("/profile/update")
    public ResponseEntity<CompanyProfileResponse> updateProfile(@CurrentUser CustomUserPrincipal user,
                                                                @Valid @RequestBody UpdateCompanyProfileRequest request) {
        var profile = companyProfileService.updateCompanyProfile(user, request);
        return ResponseEntity.ok(profile);
    }

    @GetMapping("/shipments/assigned")
    public ResponseEntity<List<ShipmentResponse>> getAssignedShipments(@CurrentUser CustomUserPrincipal user) {
        return ResponseEntity.ok(companyProfileService.getAssignedShipments(user));
    }

    @GetMapping("/shipments/{carrierId}/assigned")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<ShipmentResponse>>  getAssignedShipments(
            @PathVariable("carrierId") Long carrierId
    ) {
        return ResponseEntity.ok(companyProfileService.getAssignedShipments(carrierId));
    }

}
