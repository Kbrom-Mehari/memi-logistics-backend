package com.memilogistics.shipmentservice.entity;

import com.memilogistics.shipmentservice.enums.ShipmentStatus;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter

public class ShipmentEvent {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String description;
    private ShipmentStatus shipmentStatus;
    private String location;
    private LocalDateTime eventTimestamp;

    @ManyToOne(optional = false)
    @JoinColumn(name = "shipment_id")
    private Shipment shipment;
}
