package com.memilogistics.shipmentservice.dto;

import com.memilogistics.shipmentservice.enums.ShipmentStatus;
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
