package com.memilogistics.shipmentservice.service;

import com.memilogistics.shipmentservice.dto.AssignCarrierRequest;
import com.memilogistics.shipmentservice.dto.CancelShipmentOfferRequest;
import com.memilogistics.shipmentservice.dto.ShipmentOfferRequest;
import com.memilogistics.shipmentservice.entity.CarrierCompany;
import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.entity.ShipmentOffer;
import com.memilogistics.shipmentservice.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.repository.CarrierCompanyRepository;
import com.memilogistics.shipmentservice.repository.ShipmentOfferRepository;
import com.memilogistics.shipmentservice.repository.ShipmentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
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
    }

    @Test
    void offerShipment_ShouldCreateOfferAndSave() {
        ShipmentOfferRequest request = new ShipmentOfferRequest();
        request.setShipmentId(1L);
        request.setCarrierCompanyId(10L);
        request.setPrice(new BigDecimal("150.00"));

        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));
        when(carrierCompanyRepository.findById(10L)).thenReturn(Optional.of(sampleCarrier));

        shipmentAssignmentService.offerShipment(request);

        assertEquals(ShipmentStatus.ACCEPTED, sampleShipment.getStatus());
        assertEquals(1, sampleShipment.getShipmentOffers().size());
        verify(shipmentRepository).save(sampleShipment);
        verify(shipmentOfferRepository).save(any(ShipmentOffer.class));
    }

    @Test
    void offerShipment_ShouldThrowException_WhenShipmentNotFound() {
        ShipmentOfferRequest request = new ShipmentOfferRequest();
        request.setShipmentId(1L);

        when(shipmentRepository.findById(1L)).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> shipmentAssignmentService.offerShipment(request));
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        verify(carrierCompanyRepository, never()).findById(anyLong());
    }

    @Test
    void cancelShipmentOffer_ShouldRemoveOfferAndUpdateStatus() {
        sampleShipment.getShipmentOffers().add(sampleOffer);
        sampleCarrier.getOfferedShipments().add(sampleOffer);
        sampleShipment.setStatus(ShipmentStatus.ACCEPTED);

        CancelShipmentOfferRequest request = new CancelShipmentOfferRequest();
        request.setShipmentOfferId(100L);
        request.setCarrierId(10L);

        when(shipmentOfferRepository.findById(100L)).thenReturn(Optional.of(sampleOffer));
        when(carrierCompanyRepository.findById(10L)).thenReturn(Optional.of(sampleCarrier));

        shipmentAssignmentService.cancelShipmentOffer(request);

        assertTrue(sampleShipment.getShipmentOffers().isEmpty());
        assertTrue(sampleCarrier.getOfferedShipments().isEmpty());
        assertEquals(ShipmentStatus.PENDING, sampleShipment.getStatus()); // Should revert to PENDING
        verify(shipmentRepository).save(sampleShipment);
    }

    @Test
    void cancelShipmentOffer_ShouldThrowException_WhenCarrierDoesNotMatch() {
        CarrierCompany differentCarrier = new CarrierCompany();
        differentCarrier.setId(99L); // Malicious attempt scenario

        CancelShipmentOfferRequest request = new CancelShipmentOfferRequest();
        request.setShipmentOfferId(100L);
        request.setCarrierId(99L);

        when(shipmentOfferRepository.findById(100L)).thenReturn(Optional.of(sampleOffer));
        when(carrierCompanyRepository.findById(99L)).thenReturn(Optional.of(differentCarrier));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> shipmentAssignmentService.cancelShipmentOffer(request));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
    }

    @Test
    void assignCarrier_ShouldSetCarrierAndChangeStatus() {
        AssignCarrierRequest request = new AssignCarrierRequest();
        request.setShipmentId(1L);
        request.setCarrierId(10L);

        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));
        when(carrierCompanyRepository.findById(10L)).thenReturn(Optional.of(sampleCarrier));

        shipmentAssignmentService.assignCarrier(request);

        assertEquals(sampleCarrier, sampleShipment.getAssignedCarrier());
        assertEquals(ShipmentStatus.ASSIGNED, sampleShipment.getStatus());
        verify(shipmentRepository).save(sampleShipment);
    }
}
