package com.memilogistics.shipmentservice.mapper;

import com.memilogistics.shipmentservice.dto.AddressResponse;
import com.memilogistics.shipmentservice.dto.CarrierCompanyResponse;
import com.memilogistics.shipmentservice.dto.ShipmentResponse;
import com.memilogistics.shipmentservice.dto.ShipperProfileResponse;
import com.memilogistics.shipmentservice.entity.Address;
import com.memilogistics.shipmentservice.entity.CarrierCompany;
import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.entity.ShipperProfile;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class ShipmentMapper {

    public ShipmentResponse toResponse(Shipment shipment) {
        if (shipment == null) {
            return null;
        }

        ShipmentResponse response = new ShipmentResponse();
        response.setId(shipment.getId());
        response.setTrackingNumber(shipment.getTrackingNumber());
        response.setOrigin(shipment.getOrigin());
        response.setDestination(shipment.getDestination());
        response.setWeightKg(shipment.getWeightKg());
        response.setVolume(shipment.getVolume());
        response.setStatus(shipment.getStatus());
        response.setPickupDate(shipment.getPickupDate());
        response.setEstimatedDeliveryDate(shipment.getEstimatedDeliveryDate());
        response.setShipmentItem(shipment.getShipmentItem());
        response.setDescription(shipment.getDescription());
        response.setFragile(shipment.isFragile());
        response.setCreatedAt(shipment.getCreatedAt());
        response.setUpdatedAt(shipment.getUpdatedAt());
        response.setCompletedAt(shipment.getCompletedAt());

        if (shipment.getShipper() != null) {
            response.setShipper(toShipperProfileResponse(shipment.getShipper()));
        }

        if (shipment.getAssignedCarrier() != null) {
            response.setAssignedCarrier(toCarrierCompanyResponse(shipment.getAssignedCarrier()));
        }

        return response;
    }

    public List<ShipmentResponse> toResponseList(List<Shipment> shipments) {
        if (shipments == null) {
            return null;
        }
        return shipments.stream().map(this::toResponse).collect(Collectors.toList());
    }

    private ShipperProfileResponse toShipperProfileResponse(ShipperProfile shipper) {
        if (shipper == null) {
            return null;
        }
        ShipperProfileResponse response = new ShipperProfileResponse();
        response.setId(shipper.getId());
        response.setEmail(shipper.getEmail());
        response.setFirstName(shipper.getFirstName());
        response.setLastName(shipper.getLastName());
        response.setCompanyName(shipper.getCompanyName());
        response.setBusinessName(shipper.getBusinessName());
        response.setAddress(toAddressResponse(shipper.getAddress()));
        return response;
    }

    private CarrierCompanyResponse toCarrierCompanyResponse(CarrierCompany carrier) {
        if (carrier == null) {
            return null;
        }
        CarrierCompanyResponse response = new CarrierCompanyResponse();
        response.setId(carrier.getId());
        response.setCompanyName(carrier.getCompanyName());
        response.setCompanyEmail(carrier.getCompanyEmail());
        response.setAddress(toAddressResponse(carrier.getAddress()));
        return response;
    }

    private AddressResponse toAddressResponse(Address address) {
        if (address == null) {
            return null;
        }

        AddressResponse response = new AddressResponse();
        response.setId(address.getId());
        response.setStreet(address.getStreet());
        response.setCity(address.getCity());
        response.setState(address.getState());
        response.setZipCode(address.getZip());
        response.setCountry(address.getCountry());
        return response;
    }
}
