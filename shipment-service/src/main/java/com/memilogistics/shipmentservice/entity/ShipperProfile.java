package com.memilogistics.shipmentservice.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Setter
public class ShipperProfile {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Email
    @Column(unique = true, nullable = false)
    private String authenticationEmail; //should be auth email

    @NotBlank
    private String firstName;
    @NotBlank
    private String lastName;
    @NotBlank
    private String companyName;
    @NotBlank
    private String businessName;
    @OneToOne(orphanRemoval = true, fetch = FetchType.LAZY)
    private Address address;

    @OneToMany(
            mappedBy = "shipper",
            fetch = FetchType.LAZY,
            orphanRemoval = true,
            cascade = CascadeType.ALL
    )
    private List<Shipment> shipments = new ArrayList<>();
}
