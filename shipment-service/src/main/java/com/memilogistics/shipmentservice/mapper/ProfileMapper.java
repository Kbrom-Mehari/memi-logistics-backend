package com.memilogistics.shipmentservice.mapper;

import com.memilogistics.shipmentservice.dto.CarrierCompanyResponse;
import com.memilogistics.shipmentservice.dto.ShipperProfileResponse;
import com.memilogistics.shipmentservice.entity.Address;
import com.memilogistics.shipmentservice.entity.CarrierCompany;
import com.memilogistics.shipmentservice.entity.ShipperProfile;
import org.springframework.stereotype.Component;

@Component
public class ProfileMapper {
    public ShipperProfileResponse toShipperProfileResponse(ShipperProfile shipper) {
        if (shipper == null) {
            return null;
        }

        ShipperProfileResponse response = new ShipperProfileResponse();
        response.setId(shipper.getId());
        response.setEmail(shipper.getAuthenticationEmail());
        response.setFirstName(shipper.getFirstName());
        response.setLastName(shipper.getLastName());
        response.setCompanyName(shipper.getCompanyName());
        response.setBusinessName(shipper.getBusinessName());
        response.setAddress(shipper.getAddress());
        return response;
    }

    public CarrierCompanyResponse toCarrierCompanyResponse(CarrierCompany carrier) {
        if (carrier == null) {
            return null;
        }

        CarrierCompanyResponse response = new CarrierCompanyResponse();
        response.setId(carrier.getId());
        response.setCompanyName(carrier.getCompanyName());
        response.setCompanyEmail(carrier.getCompanyEmail());
        response.setAddress(carrier.getAddress());
        return response;
    }

}

