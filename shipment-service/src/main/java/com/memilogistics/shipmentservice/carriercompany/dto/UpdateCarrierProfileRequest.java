package com.memilogistics.shipmentservice.carriercompany.dto;

import jakarta.validation.constraints.Email;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateCarrierProfileRequest {
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
