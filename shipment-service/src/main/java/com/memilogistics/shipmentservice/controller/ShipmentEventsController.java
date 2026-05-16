package com.memilogistics.shipmentservice.controller;

import com.memilogistics.shipmentservice.entity.ShipmentEvent;
import com.memilogistics.shipmentservice.service.ShipmentEventsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/api/shipments")
@RequiredArgsConstructor
public class ShipmentEventsController {
    private final ShipmentEventsService shipmentEventsService;

    @GetMapping("/{id}/events")
    public ResponseEntity<List<ShipmentEvent>> getShipmentEvents(@PathVariable Long id) {
        try {
            var events = shipmentEventsService.getShipmentEvents(id);
            return ResponseEntity.ok(events);
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, ex.getMessage(), ex);
        }
    }
}
