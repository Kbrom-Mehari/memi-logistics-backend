package com.memilogistics.shipmentservice.dto;

import com.memilogistics.shipmentservice.entity.Address;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class CarrierCompanyResponse {
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

