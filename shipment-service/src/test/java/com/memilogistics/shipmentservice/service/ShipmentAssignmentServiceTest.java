package com.memilogistics.shipmentservice.service;

import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.carriercompany.entity.CarrierCompany;
import com.memilogistics.shipmentservice.shipment.entity.Shipment;
import com.memilogistics.shipmentservice.shipment.entity.ShipmentOffer;
import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.carriercompany.repository.CarrierCompanyRepository;
import com.memilogistics.shipmentservice.shipment.repository.ShipmentOfferRepository;
import com.memilogistics.shipmentservice.shipment.repository.ShipmentRepository;
import com.memilogistics.shipmentservice.shipment.service.ShipmentAssignmentService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class ShipmentAssignmentServiceTest {

    @Mock
    private ShipmentOfferRepository shipmentOfferRepository;

    @Mock
    private ShipmentRepository shipmentRepository;

    @Mock
    private CarrierCompanyRepository carrierCompanyRepository;

    @InjectMocks
    private ShipmentAssignmentService shipmentAssignmentService;

    private Shipment sampleShipment;
    private CarrierCompany sampleCarrier;
    private ShipmentOffer sampleOffer;
    private CustomUserPrincipal sampleUser;

    @BeforeEach
    void setUp() {
        sampleShipment = new Shipment();
        sampleShipment.setId(1L);
        sampleShipment.setStatus(ShipmentStatus.PENDING);
        sampleShipment.setShipmentOffers(new ArrayList<>());

        sampleCarrier = new CarrierCompany();
        sampleCarrier.setId(10L);
        sampleCarrier.setCompanyName("Express Logistics");
        sampleCarrier.setOfferedShipments(new ArrayList<>());

        sampleOffer = new ShipmentOffer();
        sampleOffer.setId(100L);
        sampleOffer.setShipment(sampleShipment);
        sampleOffer.setCarrierCompany(sampleCarrier);

        sampleUser = new CustomUserPrincipal("manager@express.com", List.of("ROLE_CARRIER"));
    }

    @Test
    void offerShipment_ShouldCreateOfferAndSave() {
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));
        when(carrierCompanyRepository.findByAuthenticationEmail(sampleUser.getUsername()))
                .thenReturn(Optional.of(sampleCarrier));

        shipmentAssignmentService.offerShipment(1L, sampleUser, new BigDecimal("150.00"));

        assertEquals(ShipmentStatus.ACCEPTED, sampleShipment.getStatus());
        assertEquals(1, sampleShipment.getShipmentOffers().size());
        verify(shipmentRepository).save(sampleShipment);
        verify(shipmentOfferRepository).save(any(ShipmentOffer.class));
    }

    @Test
    void offerShipment_ShouldThrowException_WhenShipmentNotFound() {
        when(shipmentRepository.findById(1L)).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> shipmentAssignmentService.offerShipment(1L, sampleUser, BigDecimal.TEN));
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        verify(carrierCompanyRepository, never()).findByAuthenticationEmail(anyString());
    }

    @Test
    void cancelShipmentOffer_ShouldRemoveOfferAndUpdateStatus() {
        sampleShipment.getShipmentOffers().add(sampleOffer);
        sampleCarrier.getOfferedShipments().add(sampleOffer);
        sampleShipment.setStatus(ShipmentStatus.ACCEPTED);

        when(shipmentOfferRepository.findById(100L)).thenReturn(Optional.of(sampleOffer));
        when(carrierCompanyRepository.findByAuthenticationEmail(sampleUser.getUsername()))
                .thenReturn(Optional.of(sampleCarrier));

        shipmentAssignmentService.cancelShipmentOffer(100L, sampleUser);

        assertTrue(sampleShipment.getShipmentOffers().isEmpty());
        assertTrue(sampleCarrier.getOfferedShipments().isEmpty());
        assertEquals(ShipmentStatus.PENDING, sampleShipment.getStatus());
        verify(shipmentRepository).save(sampleShipment);
    }

    @Test
    void cancelShipmentOffer_ShouldThrowException_WhenCarrierDoesNotMatch() {
        CarrierCompany differentCarrier = new CarrierCompany();
        differentCarrier.setId(99L);

        when(shipmentOfferRepository.findById(100L)).thenReturn(Optional.of(sampleOffer));
        when(carrierCompanyRepository.findByAuthenticationEmail(sampleUser.getUsername()))
                .thenReturn(Optional.of(differentCarrier));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> shipmentAssignmentService.cancelShipmentOffer(100L, sampleUser));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
    }

    @Test
    void assignCarrier_ShouldSetCarrierAndChangeStatus() {
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));
        when(carrierCompanyRepository.findById(10L)).thenReturn(Optional.of(sampleCarrier));

        shipmentAssignmentService.assignCarrier(1L, 10L);

        assertEquals(sampleCarrier, sampleShipment.getAssignedCarrier());
        assertEquals(ShipmentStatus.ASSIGNED, sampleShipment.getStatus());
        verify(shipmentRepository).save(sampleShipment);
    }
}
