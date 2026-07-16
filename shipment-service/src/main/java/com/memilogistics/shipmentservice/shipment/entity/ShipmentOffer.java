package com.memilogistics.shipmentservice.shipment.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.memilogistics.shipmentservice.companyprofile.entity.CompanyProfile;
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
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private LocalDateTime createdAt;

    private BigDecimal price;

    @JsonIgnore
    @ManyToOne()
    @JoinColumn(name = "shipment_id")
    private Shipment shipment;

    private String currencyCode;

    @ManyToOne()
    @JoinColumn(name = "carrier_company_id")
    private CompanyProfile carrierCompany;
}
