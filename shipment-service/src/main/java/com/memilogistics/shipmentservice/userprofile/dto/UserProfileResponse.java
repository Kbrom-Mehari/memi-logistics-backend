package com.memilogistics.shipmentservice.userprofile.dto;

import lombok.Data;

@Data
public class UserProfileResponse {
    private Long id;
    private String authenticationId;
    private String firstName;
    private String lastName;
    private String businessName;
    private String street;
    private String city;
    private String state;
    private String zip;
    private String country;
    private String phoneNumber;
}

