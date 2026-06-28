package com.memilogistics.shipmentservice.payment.entity;

import com.memilogistics.shipmentservice.payment.enums.PaymentMethod;
import com.memilogistics.shipmentservice.shipment.entity.Shipment;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Currency;

@Entity
@Getter
@Setter
public class  PaymentRecord {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @OneToOne
    @JoinColumn(name = "shipment_id", nullable = false, unique = true)
    private Shipment shipment;

    private Currency currency;

    private BigDecimal amount;

    @Enumerated(EnumType.STRING)
    private PaymentMethod paymentMethod;

    private boolean shipperConfirmed;

    private boolean carrierConfirmed;

    private LocalDateTime shipperConfirmedAt;

    private LocalDateTime carrierConfirmedAt;

    private String note;
}
