package com.memilogistics.shipmentservice.companyprofile.dto;

import lombok.Data;

@Data
public class CompanyProfileResponse {
    private Long id;
    private String companyName;
    private String companyEmail;
    private String street;
    private String city;
    private String state;
    private String zip;
    private String country;
    private String phoneNumber;
}

