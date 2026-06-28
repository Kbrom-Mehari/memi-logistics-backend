package com.memilogistics.shipmentservice.shipment.dto;

import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class StatusUpdateRequest {
    private String location;
    private ShipmentStatus status;
}
