package com.memilogistics.shipmentservice.service;

import com.memilogistics.shipmentservice.dto.ShipmentEventResponse;
import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.mapper.ShipmentEventMapper;
import com.memilogistics.shipmentservice.repository.ShipmentRepository;
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
