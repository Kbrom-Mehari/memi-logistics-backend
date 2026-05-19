package com.memilogistics.shipmentservice.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateShipperProfileRequest {
    @NotBlank(message = "First name is required")
    private String firstName;
    @NotBlank(message = "Last name is required")
    private String lastName;
    @NotBlank(message = "Company name is required")
    private String companyName;
    @NotBlank(message = "Business name is required")
    private String businessName;

    private String street;
    @NotBlank(message = "City is required")
    private String city;
    @NotBlank(message = "State is required")
    private String state;
    private String zip;
    private String country;
    private String phoneNumber;
}
