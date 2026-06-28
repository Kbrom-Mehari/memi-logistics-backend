package com.memilogistics.shipmentservice.shipment.dto;

import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import lombok.Getter;
import lombok.Setter;
import java.math.BigDecimal;
import java.time.LocalDate;

@Getter
@Setter
public class UpdateShipmentRequest {
    private String origin;
    private String destination;
    private BigDecimal weightKg;
    private LocalDate deliveryDate;
    private ShipmentStatus status;
    private String description;
}
