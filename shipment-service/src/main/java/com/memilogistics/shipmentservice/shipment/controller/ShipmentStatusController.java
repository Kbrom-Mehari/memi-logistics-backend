package com.memilogistics.shipmentservice.controller;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.ShipmentResponse;
import com.memilogistics.shipmentservice.dto.StatusUpdateRequest;
import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.service.ShipmentStatusService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/shipments")
@RequiredArgsConstructor
public class ShipmentStatusController {
    private final ShipmentStatusService shipmentStatusService;


    @PatchMapping("/{shipmentId}/update-status")
    @PreAuthorize("hasRole('CARRIER') or hasRole('ADMIN')")
    public ResponseEntity<ShipmentResponse> updateShipmentStatus(@PathVariable("shipmentId") Long id,
                                                                 @RequestBody StatusUpdateRequest request,
                                                                 @CurrentUser CustomUserPrincipal user
                                                         ) {
        if (request == null || request.getStatus() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Shipment status is required");
        }
        try {
            return ResponseEntity.ok(shipmentStatusService.updateShipmentStatus(id, request, user));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, ex.getMessage(), ex);
        }
    }
}
