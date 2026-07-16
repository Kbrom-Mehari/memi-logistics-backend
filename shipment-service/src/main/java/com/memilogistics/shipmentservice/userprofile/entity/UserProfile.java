package com.memilogistics.shipmentservice.userprofile.entity;

import com.memilogistics.shipmentservice.address.entity.Address;
import com.memilogistics.shipmentservice.companyprofile.entity.CompanyProfile;
import com.memilogistics.shipmentservice.shipment.entity.Shipment;
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
@Table(name = "user_profile")
public class UserProfile {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long profileId;

    @Column(unique = true, nullable = false)
    private String authenticationId; //should be auth id

    @NotBlank
    private String firstName;
    @NotBlank
    private String lastName;

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
    private List<Shipment> loads = new ArrayList<>();
}