package com.memilogistics.shipmentservice.dto;

import com.memilogistics.shipmentservice.entity.Address;
import lombok.Data;

@Data
public class CarrierCompanyResponse {
    private Long id;
    private String companyName;
    private String companyEmail;
    private Address address;
}

