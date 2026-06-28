package com.memilogistics.shipmentservice.shipment.dto;

import lombok.Getter;
import lombok.Setter;

import java.math.BigDecimal;

@Getter
@Setter
public class ShipmentOfferRequest {
    private Long shipmentId;
    private Long carrierCompanyId;
    private BigDecimal price;
}
