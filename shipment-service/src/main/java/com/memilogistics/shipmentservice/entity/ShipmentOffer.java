package com.memilogistics.shipmentservice.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Setter
@Getter
public class ShipmentOffer {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private LocalDateTime createdAt;

    private BigDecimal price;

    @JsonIgnore
    @ManyToOne()
    @JoinColumn(name = "shipment_id")
    private Shipment shipment;

    @ManyToOne()
    @JoinColumn(name = "carrier_company_id")
    private CarrierCompany  carrierCompany;
}
