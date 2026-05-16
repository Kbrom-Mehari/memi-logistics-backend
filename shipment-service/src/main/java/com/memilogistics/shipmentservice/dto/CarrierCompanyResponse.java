package com.memilogistics.shipmentservice.dto;

import lombok.Data;

@Data
public class CarrierCompanyResponse {
    private Long id;
    private String companyName;
    private String companyEmail;
    private AddressResponse address;
}

