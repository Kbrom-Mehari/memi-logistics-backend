package com.memilogistics.shipmentservice.service;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.ShipmentResponse;
import com.memilogistics.shipmentservice.dto.StatusUpdateRequest;
import com.memilogistics.shipmentservice.carriercompany.entity.CarrierCompany;
import com.memilogistics.shipmentservice.entity.DeliveryConfirmation;
import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.entity.ShipmentEvent;
import com.memilogistics.shipmentservice.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.exception.InvalidShipmentStatusTransitionException;
import com.memilogistics.shipmentservice.mapper.ShipmentMapper;
import com.memilogistics.shipmentservice.carriercompany.repository.CarrierCompanyRepository;
import com.memilogistics.shipmentservice.repository.ShipmentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class ShipmentStatusService {
    private final ShipmentRepository shipmentRepository;
    private final CarrierCompanyRepository carrierCompanyRepository;
    private final ShipmentMapper shipmentMapper;

    @Transactional
    public ShipmentResponse updateShipmentStatus(Long shipmentId,
                                                 StatusUpdateRequest request,
                                                 @CurrentUser CustomUserPrincipal user
    ) {
        if (request.getStatus() == null) {
            throw new IllegalArgumentException("Shipment status is required");
        }

        if(request.getStatus() == ShipmentStatus.COMPLETED){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "COMPLETED status cannot be manually set");
        }

        CarrierCompany carrierCompany = carrierCompanyRepository.findByAuthenticationEmail(user.getUsername())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Carrier company not found"));

        Shipment shipment = shipmentRepository.findById(shipmentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Shipment not found with id: " + shipmentId));

        if (shipment.getAssignedCarrier() == null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Shipment has no assigned carrier"
            );
        }

        if(!carrierCompany.getId().equals(shipment.getAssignedCarrier().getId())){
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "You are not assigned to this shipment");

        }

        if (!shipment.getStatus().canTransitionTo(request.getStatus())) {
            throw new InvalidShipmentStatusTransitionException(shipment.getStatus(), request.getStatus());
        }

        if(request.getStatus() == ShipmentStatus.DELIVERED){

            if (shipment.getDeliveryConfirmation() != null) {
                throw new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "Delivery confirmation already exists"
                );
            }

            DeliveryConfirmation deliveryConfirmation = createDeliveryConfirmation(carrierCompany);
            shipment.addDeliveryConfirmation(deliveryConfirmation);
        }

        shipment.setStatus(request.getStatus());

        var shipmentEvent = createShipmentEvent(
                request.getStatus(),
                request.getLocation(),
                "Shipment status updated to " + request.getStatus()
                );
        shipment.addShipmentEvent(shipmentEvent);

        shipmentRepository.save(shipment);
        return shipmentMapper.toResponse(shipment);
    }

    private ShipmentEvent createShipmentEvent(
            ShipmentStatus status,
            String location,
            String description
    ) {
        ShipmentEvent shipmentEvent = new ShipmentEvent();
        shipmentEvent.setLocation(location);
        shipmentEvent.setDescription(description);
        shipmentEvent.setShipmentStatus(status);
        shipmentEvent.setEventTimestamp(LocalDateTime.now());
        return shipmentEvent;
    }
    private DeliveryConfirmation createDeliveryConfirmation(CarrierCompany carrierCompany){
        DeliveryConfirmation deliveryConfirmation = new DeliveryConfirmation();
        deliveryConfirmation.setCarrierConfirmed(true);
        deliveryConfirmation.setCarrierConfirmedAt(LocalDateTime.now());
        deliveryConfirmation.setNote("Shipment delivered by carrier "
                + carrierCompany.getCompanyName()
                + " at " + LocalDateTime.now());

        return deliveryConfirmation;
    }
}
