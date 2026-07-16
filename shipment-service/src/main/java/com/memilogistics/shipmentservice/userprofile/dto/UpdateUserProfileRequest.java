package com.memilogistics.shipmentservice.userprofile.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateUserProfileRequest {
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
