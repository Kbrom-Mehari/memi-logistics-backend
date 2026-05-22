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
        response.setStreet(shipper.getAddress().getStreet());
        response.setCity(shipper.getAddress().getCity());
        response.setZip(shipper.getAddress().getZip());
        response.setState(shipper.getAddress().getState());
        response.setCountry(shipper.getAddress().getCountry());
        response.setPhoneNumber(shipper.getAddress().getPhoneNumber());
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
        response.setStreet(carrier.getAddress().getStreet());
        response.setCity(carrier.getAddress().getCity());
        response.setState(carrier.getAddress().getState());
        response.setCountry(carrier.getAddress().getCountry());
        response.setZip(carrier.getAddress().getZip());
        response.setPhoneNumber(carrier.getAddress().getPhoneNumber());
        return response;
    }


}

