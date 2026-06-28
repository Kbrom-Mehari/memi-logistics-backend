package com.memilogistics.shipmentservice.shipment.dto;

import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import lombok.Getter;
import lombok.Setter;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Getter
@Setter
public class CreateShipmentResponse {
    private Long shipmentId;
    private String trackingNumber;
    private String origin;
    private String destination;
    private BigDecimal weightKg;
    private LocalDate estimatedDeliveryDate;
    private String shipmentItem;
    private String description;
    private boolean fragile;
    private ShipmentStatus status;
    private LocalDateTime createdAt;
}
