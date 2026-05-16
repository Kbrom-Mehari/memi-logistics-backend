package com.memilogistics.shipmentservice.service;

import com.memilogistics.shipmentservice.entity.DeliveryConfirmation;
import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.entity.ShipperProfile;
import com.memilogistics.shipmentservice.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.repository.DeliveryConfirmationRepository;
import com.memilogistics.shipmentservice.repository.ShipmentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class DeliveryConfirmationServiceTest {

    @Mock
    private ShipmentRepository shipmentRepository;

    @Mock
    private DeliveryConfirmationRepository deliveryConfirmationRepository;

    @InjectMocks
    private DeliveryConfirmationService deliveryConfirmationService;

    private Shipment sampleShipment;
    private DeliveryConfirmation sampleConfirmation;
    private ShipperProfile sampleShipper;

    @BeforeEach
    void setUp() {
        sampleShipper = new ShipperProfile();
        sampleShipper.setId(10L);
        sampleShipper.setFirstName("John");
        sampleShipper.setLastName("Doe");

        sampleConfirmation = new DeliveryConfirmation();
        sampleConfirmation.setId(100L);
        sampleConfirmation.setShipperConfirmed(false);

        sampleShipment = new Shipment();
        sampleShipment.setId(1L);
        sampleShipment.setStatus(ShipmentStatus.DELIVERED);
        sampleShipment.setDeliveryConfirmation(sampleConfirmation);
        sampleShipment.setShipper(sampleShipper);
        sampleShipment.setDestination("Los Angeles");
        sampleShipment.setShipmentEvents(new ArrayList<>());
    }

    @Test
    void confirmDelivery_ShouldSucceed_WithCustomNote() {
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        deliveryConfirmationService.confirmDelivery(1L, Optional.of("Received in good condition"));

        assertTrue(sampleConfirmation.isShipperConfirmed());
        assertNotNull(sampleConfirmation.getShipperConfirmedAt());
        assertEquals("Received in good condition", sampleConfirmation.getNote());

        assertFalse(sampleShipment.getShipmentEvents().isEmpty());
        assertEquals("Delivery confirmed by shipper", sampleShipment.getShipmentEvents().get(0).getDescription());
    }

    @Test
    void confirmDelivery_ShouldSucceed_WithDefaultNote() {
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        deliveryConfirmationService.confirmDelivery(1L, Optional.empty());

        assertTrue(sampleConfirmation.isShipperConfirmed());
        assertNotNull(sampleConfirmation.getShipperConfirmedAt());
        assertTrue(sampleConfirmation.getNote().contains("Delivery confirmed by shipper John Doe"));
    }

    @Test
    void confirmDelivery_ShouldThrowException_WhenShipmentNotFound() {
        when(shipmentRepository.findById(1L)).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> deliveryConfirmationService.confirmDelivery(1L, Optional.empty()));
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Shipment not found"));
    }

    @Test
    void confirmDelivery_ShouldThrowException_WhenAlreadyCompleted() {
        sampleShipment.setStatus(ShipmentStatus.COMPLETED);
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> deliveryConfirmationService.confirmDelivery(1L, Optional.empty()));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("already completed"));
    }

    @Test
    void confirmDelivery_ShouldThrowException_WhenNotDelivered() {
        sampleShipment.setStatus(ShipmentStatus.IN_TRANSIT);
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> deliveryConfirmationService.confirmDelivery(1L, Optional.empty()));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("must be DELIVERED"));
    }

    @Test
    void confirmDelivery_ShouldThrowException_WhenConfirmationRecordNotFound() {
        sampleShipment.setDeliveryConfirmation(null);
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> deliveryConfirmationService.confirmDelivery(1L, Optional.empty()));
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertTrue(exception.getReason().contains("DeliveryConfirmation not found"));
    }

    @Test
    void confirmDelivery_ShouldThrowException_WhenAlreadyConfirmed() {
        sampleConfirmation.setShipperConfirmed(true);
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> deliveryConfirmationService.confirmDelivery(1L, Optional.empty()));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Delivery is already confirmed"));
    }
}
