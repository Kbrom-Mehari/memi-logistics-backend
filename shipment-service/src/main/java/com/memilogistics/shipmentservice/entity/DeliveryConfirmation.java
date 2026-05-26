package com.memilogistics.shipmentservice.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
public class DeliveryConfirmation {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    @OneToOne()
    @JoinColumn(name = "shipment_id", nullable = false, unique = true)
    private Shipment shipment;

    private boolean carrierConfirmed;

    private boolean shipperConfirmed;

    @Column(nullable = false)
    private LocalDateTime carrierConfirmedAt;

    @Column()
    private LocalDateTime shipperConfirmedAt;

    private String note;
}
