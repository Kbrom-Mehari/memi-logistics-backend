package com.memilogistics.shipmentservice.controller;

import com.memilogistics.shipmentservice.dto.AssignCarrierRequest;
import com.memilogistics.shipmentservice.dto.CancelShipmentOfferRequest;
import com.memilogistics.shipmentservice.dto.ShipmentOfferRequest;
import com.memilogistics.shipmentservice.service.ShipmentAssignmentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/shipments")
@RequiredArgsConstructor
public class ShipmentAssignmentController {
    private final ShipmentAssignmentService shipmentAssignmentService;


    @PostMapping("/{id}/offer-shipment")
    public ResponseEntity<Void> offerShipment(@PathVariable Long id,
                                              @RequestBody ShipmentOfferRequest request
    ) {
        shipmentAssignmentService.offerShipment(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{id}/cancel-shipment-offer")
    public ResponseEntity<Void> cancelShipmentOffer(@PathVariable Long id,
                                                    @RequestBody CancelShipmentOfferRequest request) {
        shipmentAssignmentService.cancelShipmentOffer(request);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/assign-carrier")
    public ResponseEntity<Void> assignCarrier(@PathVariable Long id,
                                              @RequestBody AssignCarrierRequest request) {
        shipmentAssignmentService.assignCarrier(request);
        return ResponseEntity.ok().build();
    }
}
