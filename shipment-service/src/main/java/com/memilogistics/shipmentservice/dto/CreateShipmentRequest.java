package com.memilogistics.shipmentservice.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import java.math.BigDecimal;
import java.time.LocalDate;

@Getter
@Setter
public class CreateShipmentRequest {
    @NotEmpty(message = "Origin is required")
    private String origin;
    @NotEmpty(message = "shipment item is required")
    private String shipmentItem;
    @NotEmpty(message = "Destination is required")
    private String destination;
    @NotNull(message = "Weight is required")
    private BigDecimal weightKg;
    @NotNull(message = "Delivery date is required")
    private LocalDate deliveryDate;
    private String description;
    private boolean fragile;
}
