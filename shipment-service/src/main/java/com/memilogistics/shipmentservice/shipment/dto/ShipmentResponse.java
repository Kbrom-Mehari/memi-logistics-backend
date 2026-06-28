package com.memilogistics.shipmentservice.shipment.dto;

import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
public class ShipmentResponse {
    private Long id;
    private String trackingNumber;
    private String origin;
    private String destination;
    private BigDecimal weightKg;
    private BigDecimal volume;
    private ShipmentStatus status;
    private LocalDate pickupDate;
    private LocalDate estimatedDeliveryDate;
    private String shipmentItem;
    private String description;
    private boolean fragile;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime completedAt;
    
    private Long shipperId;
    private Long assignedCarrierId;
}

