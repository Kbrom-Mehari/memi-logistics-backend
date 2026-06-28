package com.memilogistics.shipmentservice.shipperprofile;

import lombok.Data;

@Data
public class ShipperProfileResponse {
    private Long id;
    private String email;
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

