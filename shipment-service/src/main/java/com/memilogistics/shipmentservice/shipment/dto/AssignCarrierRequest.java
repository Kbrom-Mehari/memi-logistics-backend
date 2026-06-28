package com.memilogistics.shipmentservice.shipment.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AssignCarrierRequest {
    private Long carrierId;
    private Long ShipmentId;
}
