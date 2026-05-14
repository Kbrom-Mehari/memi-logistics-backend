package com.memilogistics.shipmentservice.service;

import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.entity.ShipmentEvent;
import com.memilogistics.shipmentservice.repository.ShipmentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ShipmentEventsService {
    private final ShipmentRepository shipmentRepository;

    public List<ShipmentEvent> getShipmentEvents(Long shipmentId) {
        Shipment shipment = shipmentRepository.findById(shipmentId)
                .orElseThrow(() -> new IllegalArgumentException("Shipment not found with id: " + shipmentId));
        return shipment.getShipmentEvents();
    }
}
