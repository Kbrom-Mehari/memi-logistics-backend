package com.memilogistics.shipmentservice.controller;

import com.memilogistics.shipmentservice.dto.StatusUpdateRequest;
import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.service.ShipmentStatusService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/shipments")
@RequiredArgsConstructor
public class ShipmentStatusController {
    private final ShipmentStatusService shipmentStatusService;


    @PatchMapping("/{id}/update-status")
    public ResponseEntity<Shipment> updateShipmentStatus(@PathVariable Long id,
                                                         @RequestBody StatusUpdateRequest request
    ) {
        if (request == null || request.getStatus() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Shipment status is required");
        }
        try {
            return ResponseEntity.ok(shipmentStatusService.updateShipmentStatus(id, request));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, ex.getMessage(), ex);
        }
    }
}
