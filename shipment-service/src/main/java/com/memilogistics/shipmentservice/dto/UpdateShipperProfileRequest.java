package com.memilogistics.shipmentservice.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateShipperProfileRequest {
    private String firstName;
    private String lastName;
    private String companyName;
    private String businessName;

    private String street;
    private String city;
    private String state;
    private String zip;
    private String country;
    private String phoneNumber;
}
