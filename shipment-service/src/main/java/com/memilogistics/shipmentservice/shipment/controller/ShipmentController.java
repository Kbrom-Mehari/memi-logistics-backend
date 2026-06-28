package com.memilogistics.shipmentservice.shipment.controller;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dashboard.DashboardInformation;
import com.memilogistics.shipmentservice.shipment.dto.*;
import com.memilogistics.shipmentservice.shipment.mapper.ShipmentMapper;
import com.memilogistics.shipmentservice.shipment.service.ShipmentService;
import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/api/shipment")
@RequiredArgsConstructor
public class ShipmentController {
    private final ShipmentService shipmentService;
    private final ShipmentMapper shipmentMapper;

    @PostMapping("/create")
    public ResponseEntity<CreateShipmentResponse> createShipment(
            @RequestBody CreateShipmentRequest request,
            @CurrentUser CustomUserPrincipal user) {
        try {
            var shipment = shipmentService.createShipment(user, request);
            URI location = URI.create(String.format("/api/shipments/tracking/%s", shipment.getTrackingNumber()));
            return ResponseEntity.created(location).body(shipment);
        } catch (IllegalArgumentException ex) {
            String message = ex.getMessage() == null ? "Invalid request" : ex.getMessage();
            if (message.toLowerCase().contains("already exists")) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, message, ex);
            }
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, message, ex);
        }
    }

    @GetMapping("/{shipmentId}")
    public ShipmentResponse getShipment(@PathVariable("shipmentId") Long id) {
        try {
            return shipmentMapper.toResponse(shipmentService.getShipment(id));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, ex.getMessage(), ex);
        }
    }
    @DeleteMapping("/{shipmentId}")
    public ResponseEntity<Void> deleteShipment(@PathVariable("shipmentId") Long id){
        shipmentService.deleteShipment(id);
        return ResponseEntity.noContent().build();

    }

    @GetMapping("/{trackingNumber}/track")
    public ResponseEntity<ShipmentResponse> getShipmentByTrackingNumber(@PathVariable("trackingNumber") String trackingNumber) {
        try {
            var shipment = shipmentService.getShipmentByTrackingNumber(trackingNumber);
            return ResponseEntity.ok(shipment);
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, ex.getMessage(), ex);
        }
    }


    @GetMapping("/{shipmentId}/offers")
    public ResponseEntity<List<ShipmentOfferResponse>> getShipmentOffers(@PathVariable("shipmentId") Long id) {
        try {
            var offers = shipmentService.getShipmentOffers(id);
            return ResponseEntity.ok(shipmentMapper.toOfferResponseList(offers));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, ex.getMessage(), ex);
        }
    }


    @GetMapping("/list")
    public ResponseEntity<List<ShipmentResponse>> listShipments(@RequestParam(name = "page", defaultValue = "0") int page,
                                        @RequestParam(name = "size", defaultValue = "20") int size) {
        var shipments = shipmentService.listShipments(page, size);
        return ResponseEntity.ok(shipments);
    }

    @GetMapping("/list/fragile")
    public ResponseEntity<List<ShipmentResponse>> listShipmentsByFragile(@RequestParam("fragile") boolean fragile,
                                                 @RequestParam(name = "page", defaultValue = "0") int page,
                                                 @RequestParam(name = "size", defaultValue = "20") int size) {
        var shipments = shipmentService.listShipmentsByFragile(fragile, page, size);
        return ResponseEntity.ok(shipments);
    }

    @GetMapping("/list-by-destination/{destination}")
    public ResponseEntity<List<ShipmentResponse>> listShipmentsByDestination(@PathVariable("destination") String destination,
                                                                     @RequestParam(name = "page", defaultValue = "0") int page,
                                                                     @RequestParam(name = "size", defaultValue = "20") int size) {
        var shipments = shipmentService.listShipmentsByDestination(destination, page, size);
        return ResponseEntity.ok(shipments);
    }

    @GetMapping("/list-by-origin/{origin}")
    public ResponseEntity<List<ShipmentResponse>> listShipmentsByOrigin(@PathVariable("origin") String origin,
                                                                @RequestParam(name = "page", defaultValue = "0") int page,
                                                                @RequestParam(name = "size", defaultValue = "20") int size) {
        var shipments = shipmentService.listShipmentsByOrigin(origin, page, size);
        return ResponseEntity.ok(shipments);
    }

    @GetMapping("/dashboard")
    public ResponseEntity<DashboardInformation> getDashboardInformation() {
        return ResponseEntity.ok(shipmentService.getDashboardInformation());
    }

    @PatchMapping("/update/{shipmentId}")
    public ResponseEntity<ShipmentResponse> updateShipment(@PathVariable("shipmentId") Long id, @RequestBody UpdateShipmentRequest update) {
        try {
            return ResponseEntity.ok(shipmentMapper.toResponse(shipmentService.updateShipment(id, update)));
        } catch (IllegalArgumentException ex) {
            String message = ex.getMessage() == null ? "Invalid request" : ex.getMessage();
            if (message.toLowerCase().contains("not found")) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, message, ex);
            }
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, message, ex);
        }
    }

    @GetMapping("/my")
    public ResponseEntity<Page<ShipmentResponse>> listMyShipments(
            @CurrentUser CustomUserPrincipal user,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size
    ) {
        return ResponseEntity.ok(shipmentService.findCurrentUserShipments(user, page, size));
    }

    @GetMapping("/my/status")
    public ResponseEntity<Page<ShipmentResponse>> listMyShipmentsByStatus(
            @CurrentUser CustomUserPrincipal user,
            @RequestParam("status") ShipmentStatus status,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size
    ) {
        return ResponseEntity.ok(shipmentService.findCurrentUserShipmentsByStatus(user, status, page, size));
    }

}
