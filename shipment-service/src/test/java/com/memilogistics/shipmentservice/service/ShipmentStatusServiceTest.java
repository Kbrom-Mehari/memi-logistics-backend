package com.memilogistics.shipmentservice.service;

import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.StatusUpdateRequest;
import com.memilogistics.shipmentservice.entity.CarrierCompany;
import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.exception.InvalidShipmentStatusTransitionException;
import com.memilogistics.shipmentservice.repository.CarrierCompanyRepository;
import com.memilogistics.shipmentservice.repository.ShipmentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class ShipmentStatusServiceTest {

    @Mock
    private ShipmentRepository shipmentRepository;

    @Mock
    private CarrierCompanyRepository carrierCompanyRepository;

    @InjectMocks
    private ShipmentStatusService shipmentStatusService;

    private Shipment sampleShipment;
    private CarrierCompany sampleCarrier;
    private StatusUpdateRequest updateRequest;
    private CustomUserPrincipal sampleUser;

    @BeforeEach
    void setUp() {
        sampleCarrier = new CarrierCompany();
        sampleCarrier.setId(10L);
        sampleCarrier.setCompanyName("Express Freight");

        sampleShipment = new Shipment();
        sampleShipment.setId(1L);
        sampleShipment.setStatus(ShipmentStatus.ASSIGNED);
        sampleShipment.setAssignedCarrier(sampleCarrier);

        updateRequest = new StatusUpdateRequest();
        updateRequest.setStatus(ShipmentStatus.PICKED_UP);
        updateRequest.setLocation("Warehouse A");

        sampleUser = new CustomUserPrincipal("manager@express.com", List.of("ROLE_CARRIER"));
    }

    @Test
    void updateShipmentStatus_ShouldUpdateStatus_WhenValid() {
        when(carrierCompanyRepository.findByAuthenticationEmail(sampleUser.getUsername()))
                .thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));
        when(shipmentRepository.save(any(Shipment.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Shipment updatedShipment = shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser);

        assertNotNull(updatedShipment);
        assertEquals(ShipmentStatus.PICKED_UP, updatedShipment.getStatus());
        assertFalse(updatedShipment.getShipmentEvents().isEmpty());
        verify(shipmentRepository).save(sampleShipment);
    }

    @Test
    void updateShipmentStatus_ShouldThrowException_WhenStatusIsNull() {
        updateRequest.setStatus(null);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser));
        assertEquals("Shipment status is required", exception.getMessage());
    }

    @Test
    void updateShipmentStatus_ShouldThrowException_WhenStatusIsCompleted() {
        updateRequest.setStatus(ShipmentStatus.COMPLETED);

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("COMPLETED status cannot be manually set"));
    }

    @Test
    void updateShipmentStatus_ShouldThrowException_WhenCarrierNotFound() {
        when(carrierCompanyRepository.findByAuthenticationEmail(sampleUser.getUsername()))
                .thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser));
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Carrier company not found"));
    }

    @Test
    void updateShipmentStatus_ShouldThrowException_WhenShipmentNotFound() {
        when(carrierCompanyRepository.findByAuthenticationEmail(sampleUser.getUsername()))
                .thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser));
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Shipment not found"));
    }

    @Test
    void updateShipmentStatus_ShouldThrowException_WhenShipmentHasNoCarrier() {
        sampleShipment.setAssignedCarrier(null);

        when(carrierCompanyRepository.findByAuthenticationEmail(sampleUser.getUsername()))
                .thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Shipment has no assigned carrier"));
    }

    @Test
    void updateShipmentStatus_ShouldThrowException_WhenWrongCarrier() {
        CarrierCompany wrongCarrier = new CarrierCompany();
        wrongCarrier.setId(99L);
        sampleShipment.setAssignedCarrier(wrongCarrier);

        when(carrierCompanyRepository.findByAuthenticationEmail(sampleUser.getUsername()))
                .thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
        assertTrue(exception.getReason().contains("not assigned to this shipment"));
    }

    @Test
    void updateShipmentStatus_ShouldThrowException_WhenInvalidTransition() {
        updateRequest.setStatus(ShipmentStatus.IN_TRANSIT);

        when(carrierCompanyRepository.findByAuthenticationEmail(sampleUser.getUsername()))
                .thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        assertThrows(InvalidShipmentStatusTransitionException.class,
                () -> shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser));
    }

    @Test
    void updateShipmentStatus_ShouldAddDeliveryConfirmation_WhenDelivered() {
        sampleShipment.setStatus(ShipmentStatus.ARRIVED_AT_DESTINATION);
        updateRequest.setStatus(ShipmentStatus.DELIVERED);

        when(carrierCompanyRepository.findByAuthenticationEmail(sampleUser.getUsername()))
                .thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));
        when(shipmentRepository.save(any(Shipment.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Shipment updatedShipment = shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser);

        assertEquals(ShipmentStatus.DELIVERED, updatedShipment.getStatus());
        assertNotNull(updatedShipment.getDeliveryConfirmation());
        verify(shipmentRepository).save(sampleShipment);
    }
}
