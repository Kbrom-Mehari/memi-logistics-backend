package com.memilogistics.shipmentservice.shipment.mapper;

import com.memilogistics.shipmentservice.shipment.dto.CreateShipmentResponse;
import com.memilogistics.shipmentservice.shipment.dto.ShipmentOfferResponse;
import com.memilogistics.shipmentservice.shipment.dto.ShipmentResponse;
import com.memilogistics.shipmentservice.shipment.entity.Shipment;
import com.memilogistics.shipmentservice.shipment.entity.ShipmentOffer;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
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
            response.setShipperId(shipment.getShipper().getId());
        }

        if (shipment.getAssignedCarrier() != null) {
            response.setAssignedCarrierId(shipment.getAssignedCarrier().getId());
        }

        return response;
    }

    public List<ShipmentResponse> toResponseList(List<Shipment> shipments) {
        if (shipments == null) {
            return null;
        }
        return shipments.stream().map(this::toResponse).collect(Collectors.toList());
    }

    public ShipmentOfferResponse toOfferResponse(ShipmentOffer offer) {
        if (offer == null) {
            return null;
        }

        ShipmentOfferResponse response = new ShipmentOfferResponse();
        response.setId(offer.getId());
        response.setCreatedAt(offer.getCreatedAt());
        response.setPrice(offer.getPrice());

        if (offer.getShipment() != null) {
            response.setShipmentId(offer.getShipment().getId());
            response.setShipmentTrackingNumber(offer.getShipment().getTrackingNumber());
        }

        if (offer.getCarrierCompany() != null) {
            response.setCarrierCompanyId(offer.getCarrierCompany().getId());
        }

        return response;
    }

    public List<ShipmentOfferResponse> toOfferResponseList(List<ShipmentOffer> offers) {
        if (offers == null) {
            return null;
        }
        return offers.stream().map(this::toOfferResponse).collect(Collectors.toList());
    }

    public CreateShipmentResponse toCreateShipmentResponse(Shipment shipment) {
        if (shipment == null) {
            return null;
        }

        CreateShipmentResponse response = new CreateShipmentResponse();
        response.setShipmentId(shipment.getId());
        response.setTrackingNumber(shipment.getTrackingNumber());
        response.setOrigin(shipment.getOrigin());
        response.setDestination(shipment.getDestination());
        response.setWeightKg(shipment.getWeightKg());
        response.setEstimatedDeliveryDate(shipment.getEstimatedDeliveryDate());
        response.setShipmentItem(shipment.getShipmentItem());
        response.setDescription(shipment.getDescription());
        response.setFragile(shipment.isFragile());
        response.setStatus(shipment.getStatus());
        response.setCreatedAt(shipment.getCreatedAt());
        return response;
    }
}
