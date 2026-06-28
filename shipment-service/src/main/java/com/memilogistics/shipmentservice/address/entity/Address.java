package com.memilogistics.shipmentservice.address.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
public class Address {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String street;
    @NotNull
    private String city;
    @NotNull
    private String state;
    private String zip;
    private String country = "Ethiopia";
    private String phoneNumber;
}
