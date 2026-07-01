package com.memilogistics.shipmentservice.companyprofile.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateCompanyProfileRequest {
    @NotBlank(message = "Company name is required")
    private String companyName;
    @NotBlank(message = "Company email is required")
    @Email(message = "Company email must be valid")
    private String companyEmail;

    private String street;
    @NotBlank(message = "City is required")
    private String city;
    @NotBlank(message = "State is required")
    private String state;
    private String zip;
    private String country;
    private String phoneNumber;
}
