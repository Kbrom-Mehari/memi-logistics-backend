package com.memilogistics.shipmentservice.dto;

import com.memilogistics.shipmentservice.entity.Address;
import lombok.Data;

@Data
public class ShipperProfileResponse {
    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private String companyName;
    private String businessName;
    private Address address;
}

