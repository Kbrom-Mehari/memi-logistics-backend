package com.memilogistics.shipmentservice.controller;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.AssignCarrierRequest;
import com.memilogistics.shipmentservice.dto.CancelShipmentOfferRequest;
import com.memilogistics.shipmentservice.dto.ShipmentOfferRequest;
import com.memilogistics.shipmentservice.service.ShipmentAssignmentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;

@RestController
@RequestMapping("/api/shipments")
@RequiredArgsConstructor
public class ShipmentAssignmentController {
    private final ShipmentAssignmentService shipmentAssignmentService;


    @PostMapping("/{shipmentId}/offer-shipment")
    @PreAuthorize("hasRole('CARRIER') or hasRole('ADMIN')")
    public ResponseEntity<Void> offerShipment(@PathVariable("shipmentId") Long shipmentId,
                                              @RequestParam("price") BigDecimal price,
                                              @CurrentUser CustomUserPrincipal user
                                              ) {
        shipmentAssignmentService.offerShipment(shipmentId, user, price);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{shipmentOfferId}/cancel-shipment-offer")
    @PreAuthorize("hasRole('CARRIER') or hasRole('ADMIN')")
    public ResponseEntity<Void> cancelShipmentOffer(@PathVariable("shipmentOfferId") Long shipmentOfferId,
                                                    @CurrentUser CustomUserPrincipal user) {
        shipmentAssignmentService.cancelShipmentOffer(shipmentOfferId, user);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{shipmentId}/assign-carrier")
    @PreAuthorize("hasRole('SHIPPER') or hasRole('ADMIN')")
    public ResponseEntity<Void> assignCarrier(@PathVariable("shipmentId") Long shipmentId,
                                              @RequestParam("carrierId") Long carrierId) {
        shipmentAssignmentService.assignCarrier(shipmentId, carrierId);
        return ResponseEntity.ok().build();
    }
}
