package com.memilogistics.shipmentservice.dto;

import com.memilogistics.shipmentservice.enums.ShipmentStatus;
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
}
