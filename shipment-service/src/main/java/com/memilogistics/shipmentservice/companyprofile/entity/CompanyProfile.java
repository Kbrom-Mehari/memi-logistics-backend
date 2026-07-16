package com.memilogistics.shipmentservice.companyprofile.entity;

import com.memilogistics.shipmentservice.address.entity.Address;
import com.memilogistics.shipmentservice.shipment.entity.Shipment;
import com.memilogistics.shipmentservice.shipment.entity.ShipmentOffer;
import com.memilogistics.shipmentservice.userprofile.entity.UserProfile;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Setter
@Getter
@Entity
public class CompanyProfile {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long companyProfileId;

    private String companyName;
    @Email
    private String companyEmail;
    @OneToOne(fetch = FetchType.LAZY, orphanRemoval = true)
    private Address address;

    @Column(nullable = false)
    private String authenticationId;

    @OneToMany(
            fetch = FetchType.LAZY,
            mappedBy = "carrierCompany"
    )
    private List<ShipmentOffer> offeredShipments = new ArrayList<>();

    @OneToMany(
            mappedBy = "assignedCarrier",
            fetch = FetchType.LAZY,
            orphanRemoval = true,
            cascade = CascadeType.ALL
    )
    private List<Shipment> assignedShipments = new ArrayList<>();
}
