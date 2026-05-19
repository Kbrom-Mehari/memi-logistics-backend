package com.memilogistics.shipmentservice.service;

import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.CreateShipmentRequest;
import com.memilogistics.shipmentservice.dto.DashboardInformation;
import com.memilogistics.shipmentservice.dto.UpdateShipmentRequest;
import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.entity.ShipmentEvent;
import com.memilogistics.shipmentservice.entity.ShipperProfile;
import com.memilogistics.shipmentservice.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.repository.ShipmentRepository;
import com.memilogistics.shipmentservice.repository.ShipperProfileRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class ShipmentServiceTest {

    @Mock
    private ShipmentRepository shipmentRepository;

    @Mock
    private ShipperProfileRepository shipperProfileRepository;

    @InjectMocks
    private ShipmentService shipmentService;

    private Shipment sampleShipment;
    private ShipperProfile sampleShipper;
    private CustomUserPrincipal sampleUser;

    @BeforeEach
    void setUp() {
        sampleShipment = new Shipment();
        sampleShipment.setId(1L);
        sampleShipment.setTrackingNumber("TRK-123456789012");
        sampleShipment.setDestination("New York");
        sampleShipment.setOrigin("Los Angeles");
        sampleShipment.setFragile(false);
        sampleShipment.setStatus(ShipmentStatus.PENDING);
        sampleShipment.setShipmentEvents(new ArrayList<>());

        sampleShipper = new ShipperProfile();
        sampleShipper.setId(7L);
        sampleShipper.setEmail("shipper@example.com");

        sampleUser = new CustomUserPrincipal("shipper@example.com", List.of("ROLE_SHIPPER"));
    }

    @Test
    void createShipment_ShouldReturnCreatedShipment() {
        CreateShipmentRequest request = new CreateShipmentRequest();
        request.setOrigin("Los Angeles");
        request.setDestination("New York");
        request.setWeightKg(new BigDecimal("10.5"));
        request.setDeliveryDate(LocalDate.now().plusDays(5));
        request.setFragile(true);
        request.setShipmentItem("Electronics");

        when(shipperProfileRepository.findByEmail(sampleUser.getUsername()))
                .thenReturn(Optional.of(sampleShipper));
        when(shipmentRepository.findByTrackingNumber(anyString())).thenReturn(Optional.empty());
        when(shipmentRepository.save(any(Shipment.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Shipment createdShipment = shipmentService.createShipment(sampleUser, request);

        assertNotNull(createdShipment);
        assertNotNull(createdShipment.getTrackingNumber());
        assertEquals("Los Angeles", createdShipment.getOrigin());
        assertEquals("New York", createdShipment.getDestination());
        assertTrue(createdShipment.isFragile());
        assertEquals(sampleShipper, createdShipment.getShipper());
        assertEquals(1, createdShipment.getShipmentEvents().size());

        verify(shipmentRepository).save(any(Shipment.class));
    }

    @Test
    void getShipment_ShouldReturnShipment_WhenIdExists() {
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        Shipment result = shipmentService.getShipment(1L);

        assertNotNull(result);
        assertEquals(1L, result.getId());
    }

    @Test
    void getShipment_ShouldThrowException_WhenIdDoesNotExist() {
        when(shipmentRepository.findById(2L)).thenReturn(Optional.empty());

        assertThrows(IllegalArgumentException.class, () -> shipmentService.getShipment(2L));
    }

    @Test
    void listShipments_ShouldReturnShipmentList() {
        List<Shipment> shipments = List.of(sampleShipment);
        Page<Shipment> shipmentPage = new PageImpl<>(shipments);

        when(shipmentRepository.findAll(any(Pageable.class))).thenReturn(shipmentPage);

        List<Shipment> result = shipmentService.listShipments(0, 10);

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(shipmentRepository).findAll(any(Pageable.class));
    }

    @Test
    void updateShipment_ShouldUpdateAndReturnShipment() {
        UpdateShipmentRequest updateRequest = new UpdateShipmentRequest();
        updateRequest.setDestination("San Francisco");

        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));
        when(shipmentRepository.save(any(Shipment.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Shipment updatedShipment = shipmentService.updateShipment(1L, updateRequest);

        assertNotNull(updatedShipment);
        assertEquals("San Francisco", updatedShipment.getDestination());
        verify(shipmentRepository).save(any(Shipment.class));
    }

    @Test
    void getDashboardInformation_ShouldReturnDashboardData() {
        when(shipmentRepository.countByStatus(ShipmentStatus.PENDING)).thenReturn(5L);
        when(shipmentRepository.countByStatus(ShipmentStatus.DELIVERED)).thenReturn(10L);
        when(shipmentRepository.countByFragile(true)).thenReturn(3L);
        when(shipmentRepository.countByFragile(false)).thenReturn(12L);

        DashboardInformation info = shipmentService.getDashboardInformation();

        assertNotNull(info);
        assertEquals(5L, info.getPendingShipments());
        assertEquals(10L, info.getCompletedShipments());
        assertEquals(3L, info.getFragileShipments());
        assertEquals(12L, info.getNonFragileShipments());
    }
}
