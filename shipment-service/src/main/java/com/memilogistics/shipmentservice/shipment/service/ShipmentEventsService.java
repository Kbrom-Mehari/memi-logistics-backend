package com.memilogistics.shipmentservice.shipment.service;

import com.memilogistics.shipmentservice.shipment.dto.ShipmentEventResponse;
import com.memilogistics.shipmentservice.shipment.entity.Shipment;
import com.memilogistics.shipmentservice.shipment.mapper.ShipmentEventMapper;
import com.memilogistics.shipmentservice.shipment.repository.ShipmentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ShipmentEventsService {
    private final ShipmentRepository shipmentRepository;
    private final ShipmentEventMapper shipmentEventMapper;

    public List<ShipmentEventResponse> getShipmentEvents(Long shipmentId) {
        Shipment shipment = shipmentRepository.findById(shipmentId)
                .orElseThrow(() -> new IllegalArgumentException("Shipment not found with id: " + shipmentId));
        return shipmentEventMapper.toResponseList(shipment.getShipmentEvents());
    }
}
