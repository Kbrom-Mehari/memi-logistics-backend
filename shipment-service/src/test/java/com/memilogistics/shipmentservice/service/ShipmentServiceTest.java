package com.memilogistics.shipmentservice.service;

import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.CreateShipmentRequest;
import com.memilogistics.shipmentservice.dto.CreateShipmentResponse;
import com.memilogistics.shipmentservice.dto.DashboardInformation;
import com.memilogistics.shipmentservice.dto.ShipmentResponse;
import com.memilogistics.shipmentservice.dto.UpdateShipmentRequest;
import com.memilogistics.shipmentservice.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.entity.ShipperProfile;
import com.memilogistics.shipmentservice.repository.ShipmentRepository;
import com.memilogistics.shipmentservice.repository.ShipperProfileRepository;
import com.memilogistics.shipmentservice.mapper.ShipmentMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.PageRequest;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
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

    @org.mockito.Spy
    private ShipmentMapper shipmentMapper;

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
        sampleShipper.setAuthenticationEmail("shipper@example.com");
        sampleShipper.setFirstName("Alex");
        sampleShipper.setLastName("Smith");
        sampleShipper.setCompanyName("Memi Logistics");
        sampleShipper.setBusinessName("Memi Shippers");

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
        request.setDescription("Handle with care");

        when(shipperProfileRepository.findByAuthenticationEmail(sampleUser.getUsername()))
                .thenReturn(Optional.of(sampleShipper));
        when(shipmentRepository.findByTrackingNumber(anyString())).thenReturn(Optional.empty());
        when(shipmentRepository.save(any(Shipment.class))).thenAnswer(invocation -> {
            Shipment saved = invocation.getArgument(0);
            saved.setId(1L);
            if (saved.getStatus() == null) {
                saved.setStatus(ShipmentStatus.PENDING);
            }
            if (saved.getCreatedAt() == null) {
                saved.setCreatedAt(LocalDateTime.now());
            }
            return saved;
        });

        CreateShipmentResponse createdShipment = shipmentService.createShipment(sampleUser, request);

        assertNotNull(createdShipment);
        assertNotNull(createdShipment.getShipmentId());
        assertNotNull(createdShipment.getTrackingNumber());
        assertEquals("Los Angeles", createdShipment.getOrigin());
        assertEquals("New York", createdShipment.getDestination());
        assertEquals("Electronics", createdShipment.getShipmentItem());
        assertEquals("Handle with care", createdShipment.getDescription());
        assertTrue(createdShipment.isFragile());

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

        List<ShipmentResponse> result = shipmentService.listShipments(0, 10);

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

    @Test
    void findCurrentUserShipments_ShouldReturnMappedPage() {
        Shipment ownedShipment = new Shipment();
        ownedShipment.setId(5L);
        ownedShipment.setTrackingNumber("TRK-OWNED-123456");
        ownedShipment.setOrigin("Addis Ababa");
        ownedShipment.setDestination("Nairobi");
        ownedShipment.setShipper(sampleShipper);
        ownedShipment.setStatus(ShipmentStatus.PENDING);

        Page<Shipment> shipmentPage = new PageImpl<>(List.of(ownedShipment), PageRequest.of(0, 10), 1);

        when(shipmentRepository.findByShipperAuthenticationEmail(eq(sampleUser.getUsername()), any(Pageable.class)))
                .thenReturn(shipmentPage);

        Page<ShipmentResponse> responses = shipmentService.findCurrentUserShipments(sampleUser, 0, 10);

        assertEquals(1, responses.getContent().size());
        assertEquals("TRK-OWNED-123456", responses.getContent().get(0).getTrackingNumber());
        assertEquals("Addis Ababa", responses.getContent().get(0).getOrigin());
        assertEquals("Nairobi", responses.getContent().get(0).getDestination());
    }

    @Test
    void findCurrentUserShipmentsByStatus_ShouldFilterByStatus() {
        Shipment deliveredShipment = new Shipment();
        deliveredShipment.setId(11L);
        deliveredShipment.setTrackingNumber("TRK-DELIVERED");
        deliveredShipment.setOrigin("Addis Ababa");
        deliveredShipment.setDestination("Kigali");
        deliveredShipment.setStatus(ShipmentStatus.DELIVERED);
        deliveredShipment.setShipper(sampleShipper);

        Page<Shipment> shipmentPage = new PageImpl<>(List.of(deliveredShipment), PageRequest.of(0, 10), 1);

        when(shipmentRepository.findByShipperAuthenticationEmailAndStatus(
                eq(sampleUser.getUsername()),
                eq(ShipmentStatus.DELIVERED),
                any(Pageable.class)
        )).thenReturn(shipmentPage);

        Page<ShipmentResponse> responses = shipmentService.findCurrentUserShipmentsByStatus(
                sampleUser,
                ShipmentStatus.DELIVERED,
                0,
                10
        );

        assertEquals(1, responses.getContent().size());
        assertEquals("TRK-DELIVERED", responses.getContent().get(0).getTrackingNumber());
    }
}
