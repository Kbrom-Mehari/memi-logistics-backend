package com.memilogistics.shipmentservice.dto;

import com.memilogistics.shipmentservice.enums.ShipmentStatus;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class StatusUpdateRequest {
    private String location;
    private ShipmentStatus status;
}
