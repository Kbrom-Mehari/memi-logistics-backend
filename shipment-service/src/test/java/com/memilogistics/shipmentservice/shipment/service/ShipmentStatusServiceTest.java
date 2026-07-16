package com.memilogistics.shipmentservice.shipment.service;

import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.shipment.dto.ShipmentResponse;
import com.memilogistics.shipmentservice.shipment.dto.StatusUpdateRequest;
import com.memilogistics.shipmentservice.companyprofile.entity.CompanyProfile;
import com.memilogistics.shipmentservice.shipment.entity.Shipment;
import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.exception.InvalidShipmentStatusTransitionException;
import com.memilogistics.shipmentservice.shipment.mapper.ShipmentMapper;
import com.memilogistics.shipmentservice.companyprofile.repository.CompanyProfileRepository;
import com.memilogistics.shipmentservice.shipment.repository.ShipmentRepository;
import com.memilogistics.shipmentservice.shipment.service.ShipmentStatusService;
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
    private CompanyProfileRepository companyRepository;

    @Mock
    private ShipmentMapper shipmentMapper;

    @InjectMocks
    private ShipmentStatusService shipmentStatusService;

    private Shipment sampleShipment;
    private CompanyProfile sampleCarrier;
    private StatusUpdateRequest updateRequest;
    private CustomUserPrincipal sampleUser;

    @BeforeEach
    void setUp() {
        sampleCarrier = new CompanyProfile();
        sampleCarrier.setCompanyProfileId(10L);
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
        ShipmentResponse response = new ShipmentResponse();
        response.setId(sampleShipment.getId());
        response.setStatus(ShipmentStatus.PICKED_UP);

        when(companyRepository.findByAuthenticationId(sampleUser.getId()))
                .thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));
        when(shipmentRepository.save(any(Shipment.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(shipmentMapper.toResponse(sampleShipment)).thenReturn(response);

        ShipmentResponse updatedShipment = shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser);

        assertNotNull(updatedShipment);
        assertEquals(ShipmentStatus.PICKED_UP, updatedShipment.getStatus());
        assertFalse(sampleShipment.getShipmentEvents().isEmpty());
        verify(shipmentRepository).save(sampleShipment);
        verify(shipmentMapper).toResponse(sampleShipment);
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
        assert exception.getReason() != null;
        assertTrue(exception.getReason().contains("COMPLETED status cannot be manually set"));
    }

    @Test
    void updateShipmentStatus_ShouldThrowException_WhenCarrierNotFound() {
        when(companyRepository.findByAuthenticationId(sampleUser.getId()))
                .thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser));
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        assert exception.getReason() != null;
        assertTrue(exception.getReason().contains("Carrier company not found"));
    }

    @Test
    void updateShipmentStatus_ShouldThrowException_WhenShipmentNotFound() {
        when(companyRepository.findByAuthenticationId(sampleUser.getId()))
                .thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser));
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        assert exception.getReason() != null;
        assertTrue(exception.getReason().contains("Shipment not found"));
    }

    @Test
    void updateShipmentStatus_ShouldThrowException_WhenShipmentHasNoCarrier() {
        sampleShipment.setAssignedCarrier(null);

        when(companyRepository.findByAuthenticationId(sampleUser.getId()))
                .thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assert exception.getReason() != null;
        assertTrue(exception.getReason().contains("Shipment has no assigned carrier"));
    }

    @Test
    void updateShipmentStatus_ShouldThrowException_WhenWrongCarrier() {
        CompanyProfile wrongCarrier = new CompanyProfile();
        wrongCarrier.setCompanyProfileId(99L);
        sampleShipment.setAssignedCarrier(wrongCarrier);

        when(companyRepository.findByAuthenticationId(sampleUser.getId()))
                .thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
        assert exception.getReason() != null;
        assertTrue(exception.getReason().contains("not assigned to this shipment"));
    }

    @Test
    void updateShipmentStatus_ShouldThrowException_WhenInvalidTransition() {
        updateRequest.setStatus(ShipmentStatus.IN_TRANSIT);

        when(companyRepository.findByAuthenticationId(sampleUser.getId()))
                .thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        assertThrows(InvalidShipmentStatusTransitionException.class,
                () -> shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser));
    }

    @Test
    void updateShipmentStatus_ShouldAddDeliveryConfirmation_WhenDelivered() {
        ShipmentResponse response = new ShipmentResponse();
        response.setId(sampleShipment.getId());
        response.setStatus(ShipmentStatus.DELIVERED);

        sampleShipment.setStatus(ShipmentStatus.ARRIVED_AT_DESTINATION);
        updateRequest.setStatus(ShipmentStatus.DELIVERED);

        when(companyRepository.findByAuthenticationId(sampleUser.getId()))
                .thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));
        when(shipmentRepository.save(any(Shipment.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(shipmentMapper.toResponse(sampleShipment)).thenReturn(response);

        ShipmentResponse updatedShipment = shipmentStatusService.updateShipmentStatus(1L, updateRequest, sampleUser);

        assertEquals(ShipmentStatus.DELIVERED, updatedShipment.getStatus());
        assertNotNull(sampleShipment.getDeliveryConfirmation());
        verify(shipmentRepository).save(sampleShipment);
        verify(shipmentMapper).toResponse(sampleShipment);
    }
}
