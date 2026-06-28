package com.memilogistics.shipmentservice.service;

import com.memilogistics.shipmentservice.payment.dto.PaymentRequest;
import com.memilogistics.shipmentservice.carriercompany.entity.CarrierCompany;
import com.memilogistics.shipmentservice.payment.entity.PaymentRecord;
import com.memilogistics.shipmentservice.payment.service.PaymentRecordService;
import com.memilogistics.shipmentservice.shipment.entity.Shipment;
import com.memilogistics.shipmentservice.payment.enums.PaymentMethod;
import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.carriercompany.repository.CarrierCompanyRepository;
import com.memilogistics.shipmentservice.shipment.repository.ShipmentRepository;
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
import java.util.Currency;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class PaymentRecordServiceTest {

    @Mock
    private ShipmentRepository shipmentRepository;

    @Mock
    private CarrierCompanyRepository carrierCompanyRepository;

    @InjectMocks
    private PaymentRecordService paymentRecordService;

    private Shipment sampleShipment;
    private CarrierCompany sampleCarrier;
    private PaymentRequest paymentRequest;
    private PaymentRecord samplePaymentRecord;
    private CustomUserPrincipal mockPrincipal;

    @BeforeEach
    void setUp() {
        sampleCarrier = new CarrierCompany();
        sampleCarrier.setId(10L);
        sampleCarrier.setCompanyName("Express Freight");

        mockPrincipal = mock(CustomUserPrincipal.class);
        lenient().when(mockPrincipal.getUsername()).thenReturn("carrier@test.com");

        sampleShipment = new Shipment();
        sampleShipment.setId(1L);
        sampleShipment.setStatus(ShipmentStatus.DELIVERED);
        sampleShipment.setDestination("New York");
        sampleShipment.setAssignedCarrier(sampleCarrier);
        sampleShipment.setShipmentEvents(new ArrayList<>());

        // DTOs and sub-entities
        paymentRequest = new PaymentRequest();
        paymentRequest.setAmount(new BigDecimal("250.00"));
        paymentRequest.setPaymentMethod(PaymentMethod.BANK_TRANSFER);
        paymentRequest.setNote("Payment for delivery");
        paymentRequest.setCurrencyCode("USD");

        samplePaymentRecord = new PaymentRecord();
        samplePaymentRecord.setId(100L);
        samplePaymentRecord.setShipperConfirmed(true);
        samplePaymentRecord.setCarrierConfirmed(false);
    }

    @Test
    void initiatePayment_ShouldSucceed_WhenValid() {
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        paymentRecordService.initiatePayment(1L, paymentRequest);

        assertNotNull(sampleShipment.getPaymentRecord());
        assertTrue(sampleShipment.getPaymentRecord().isShipperConfirmed());
        assertEquals(new BigDecimal("250.00"), sampleShipment.getPaymentRecord().getAmount());
        assertEquals(Currency.getInstance("USD"), sampleShipment.getPaymentRecord().getCurrency());
        assertFalse(sampleShipment.getShipmentEvents().isEmpty());
        // Since @Transactional manages saving implicitly via dirty checking, we don't strictly assert save()
    }

    @Test
    void initiatePayment_ShouldThrowException_WhenShipmentNotFound() {
        when(shipmentRepository.findById(1L)).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> paymentRecordService.initiatePayment(1L, paymentRequest));
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
    }

    @Test
    void initiatePayment_ShouldThrowException_WhenNotDelivered() {
        sampleShipment.setStatus(ShipmentStatus.IN_TRANSIT);
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> paymentRecordService.initiatePayment(1L, paymentRequest));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Shipment must be DELIVERED"));
    }

    @Test
    void initiatePayment_ShouldThrowException_WhenAlreadyInitiated() {
        sampleShipment.setPaymentRecord(new PaymentRecord());
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> paymentRecordService.initiatePayment(1L, paymentRequest));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Payment already initiated"));
    }

    @Test
    void confirmPayment_ShouldSucceed_WhenValid() {
        sampleShipment.setPaymentRecord(samplePaymentRecord);
        when(carrierCompanyRepository.findByAuthenticationEmail("carrier@test.com")).thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        paymentRecordService.confirmPayment(1L, mockPrincipal);

        assertTrue(samplePaymentRecord.isCarrierConfirmed());
        assertNotNull(samplePaymentRecord.getCarrierConfirmedAt());
        assertEquals(ShipmentStatus.COMPLETED, sampleShipment.getStatus());
        // assertNotNull(sampleShipment.getCompletedAt());
        assertFalse(sampleShipment.getShipmentEvents().isEmpty());
    }

    @Test
    void confirmPayment_ShouldThrowException_WhenShipmentNotFound() {
        when(carrierCompanyRepository.findByAuthenticationEmail("carrier@test.com")).thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> paymentRecordService.confirmPayment(1L, mockPrincipal));
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
    }

    @Test
    void confirmPayment_ShouldThrowException_WhenNoAssignedCarrier() {
        sampleShipment.setAssignedCarrier(null);
        when(carrierCompanyRepository.findByAuthenticationEmail("carrier@test.com")).thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> paymentRecordService.confirmPayment(1L, mockPrincipal));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Shipment has no assigned carrier"));
    }

    @Test
    void confirmPayment_ShouldThrowException_WhenWrongCarrier() {
        CarrierCompany wrongCarrier = new CarrierCompany();
        wrongCarrier.setId(99L);
        sampleShipment.setAssignedCarrier(wrongCarrier);
        when(carrierCompanyRepository.findByAuthenticationEmail("carrier@test.com")).thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> paymentRecordService.confirmPayment(1L, mockPrincipal));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Carrier not assigned to this shipment"));
    }

    @Test
    void confirmPayment_ShouldThrowException_WhenPaymentNotInitiated() {
        sampleShipment.setPaymentRecord(null); // No payment record
        when(carrierCompanyRepository.findByAuthenticationEmail("carrier@test.com")).thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> paymentRecordService.confirmPayment(1L, mockPrincipal));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Payment is not initiated"));
    }

    @Test
    void confirmPayment_ShouldThrowException_WhenNotShipperConfirmed() {
        samplePaymentRecord.setShipperConfirmed(false);
        sampleShipment.setPaymentRecord(samplePaymentRecord);
        when(carrierCompanyRepository.findByAuthenticationEmail("carrier@test.com")).thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> paymentRecordService.confirmPayment(1L, mockPrincipal));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Payment not initiated by shipper"));
    }

    @Test
    void confirmPayment_ShouldThrowException_WhenAlreadyCarrierConfirmed() {
        samplePaymentRecord.setCarrierConfirmed(true);
        sampleShipment.setPaymentRecord(samplePaymentRecord);
        when(carrierCompanyRepository.findByAuthenticationEmail("carrier@test.com")).thenReturn(Optional.of(sampleCarrier));
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> paymentRecordService.confirmPayment(1L, mockPrincipal));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("Payment is already confirmed by carrier"));
    }
}