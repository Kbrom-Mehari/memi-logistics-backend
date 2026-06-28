package com.memilogistics.shipmentservice.shipment.mapper;

import com.memilogistics.shipmentservice.shipment.dto.ShipmentEventResponse;
import com.memilogistics.shipmentservice.shipment.entity.ShipmentEvent;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class ShipmentEventMapper {

    public ShipmentEventResponse toResponse(ShipmentEvent event) {
        if (event == null) {
            return null;
        }

        ShipmentEventResponse response = new ShipmentEventResponse();
        response.setId(event.getId());
        response.setDescription(event.getDescription());
        response.setShipmentStatus(event.getShipmentStatus());
        response.setLocation(event.getLocation());
        response.setEventTimestamp(event.getEventTimestamp());
        if (event.getShipment() != null) {
            response.setShipmentId(event.getShipment().getId());
        }
        return response;
    }

    public List<ShipmentEventResponse> toResponseList(List<ShipmentEvent> events) {
        if (events == null) {
            return null;
        }
        return events.stream().map(this::toResponse).collect(Collectors.toList());
    }
}

