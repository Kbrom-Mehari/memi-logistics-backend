package com.memilogistics.shipmentservice.dto;

import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
public class ShipmentOfferResponse {
    private Long id;
    private LocalDateTime createdAt;
    private BigDecimal price;
    private Long shipmentId;
    private String shipmentTrackingNumber;
    private Long carrierCompanyId;
}

