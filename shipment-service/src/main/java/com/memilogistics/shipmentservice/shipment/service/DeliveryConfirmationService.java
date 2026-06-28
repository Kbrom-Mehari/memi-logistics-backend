package com.memilogistics.shipmentservice.shipment.service;

import com.memilogistics.shipmentservice.shipment.entity.ShipmentEvent;
import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.shipment.repository.DeliveryConfirmationRepository;
import com.memilogistics.shipmentservice.shipment.repository.ShipmentRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class DeliveryConfirmationService {
    private final ShipmentRepository shipmentRepository;
    private final DeliveryConfirmationRepository deliveryConfirmationRepository;

    @Transactional
    public void confirmDelivery(Long shipmentId, Optional<String> note) {
        var shipment = shipmentRepository.findById(shipmentId).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.NOT_FOUND,"Shipment not found with id: " + shipmentId)
        );

        if (shipment.getStatus() == ShipmentStatus.COMPLETED) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Shipment is already completed");
        }

        if (shipment.getStatus() != ShipmentStatus.DELIVERED) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Shipment must be DELIVERED before confirmation");
        }

        var deliveryConfirmation = shipment.getDeliveryConfirmation();
        if (deliveryConfirmation == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "DeliveryConfirmation not found");
        }

        if(deliveryConfirmation.isShipperConfirmed()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Delivery is already confirmed");
        }

        deliveryConfirmation.setShipperConfirmed(true);
        deliveryConfirmation.setShipperConfirmedAt(LocalDateTime.now());
        deliveryConfirmation.setNote
                (note.orElse
                        ("Delivery confirmed by shipper "
                                + shipment.getShipper().getFirstName()
                                + " " + shipment.getShipper().getLastName()
                                + " at " + LocalDateTime.now()));

        ShipmentEvent shipmentEvent = new ShipmentEvent();

        shipmentEvent.setShipmentStatus(shipment.getStatus());
        shipmentEvent.setEventTimestamp(LocalDateTime.now());
        shipmentEvent.setLocation(shipment.getDestination());
        shipmentEvent.setDescription("Delivery confirmed by shipper");

        shipment.addShipmentEvent(shipmentEvent);
    }

}
