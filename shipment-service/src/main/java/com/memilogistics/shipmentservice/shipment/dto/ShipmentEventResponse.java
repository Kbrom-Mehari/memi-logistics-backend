package com.memilogistics.shipmentservice.shipment.dto;

import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class ShipmentEventResponse {
    private Long id;
    private Long shipmentId;
    private String description;
    private ShipmentStatus shipmentStatus;
    private String location;
    private LocalDateTime eventTimestamp;
}
