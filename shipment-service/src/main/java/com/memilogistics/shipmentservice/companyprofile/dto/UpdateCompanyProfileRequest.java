package com.memilogistics.shipmentservice.companyprofile.dto;

import jakarta.validation.constraints.Email;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateCompanyProfileRequest {
    private String companyName;
    @Email(message = "Company email must be valid")
    private String companyEmail;

    private String street;
    private String city;
    private String state;
    private String zip;
    private String country;
    private String phoneNumber;
}
