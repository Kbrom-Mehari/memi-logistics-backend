package com.memilogistics.shipmentservice.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Setter
@Getter
@Entity
public class CarrierCompany {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String managerUserId;

    private String companyName;

    @OneToOne(fetch = FetchType.LAZY)
    private Address address;

    private String managerEmail;

    @Email
    private String companyEmail;

    @OneToMany(
            fetch = FetchType.LAZY,
            mappedBy = "assignedCarrier"
    )
    private List<Shipment> assignedShipments = new ArrayList<>();

    @OneToMany(
            fetch = FetchType.LAZY,
            mappedBy = "carrierCompany"
    )
    private List<ShipmentOffer> offeredShipments = new ArrayList<>();
}
