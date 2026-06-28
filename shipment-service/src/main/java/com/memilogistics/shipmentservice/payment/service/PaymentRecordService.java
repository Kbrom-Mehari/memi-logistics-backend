package com.memilogistics.shipmentservice.service;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.payment.dto.PaymentRequest;
import com.memilogistics.shipmentservice.carriercompany.entity.CarrierCompany;
import com.memilogistics.shipmentservice.payment.entity.PaymentRecord;
import com.memilogistics.shipmentservice.shipment.entity.Shipment;
import com.memilogistics.shipmentservice.shipment.entity.ShipmentEvent;
import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.carriercompany.repository.CarrierCompanyRepository;
import com.memilogistics.shipmentservice.repository.PaymentRecordRepository;
import com.memilogistics.shipmentservice.shipment.repository.ShipmentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Currency;

@Service
@RequiredArgsConstructor
public class PaymentRecordService {
    private final ShipmentRepository shipmentRepository;
    private final CarrierCompanyRepository carrierCompanyRepository;
    private final PaymentRecordRepository paymentRecordRepository;


    @Transactional
    public void initiatePayment(
            Long shipmentId,
            PaymentRequest request
    ) {

        Shipment shipment = shipmentRepository.findById(shipmentId).orElseThrow(
                ()-> new ResponseStatusException(HttpStatus.NOT_FOUND, "shipment with id "+shipmentId+" not found")
        );

        if (shipment.getStatus() != ShipmentStatus.DELIVERED) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Shipment must be DELIVERED"
            );
        }

        if (shipment.getPaymentRecord() != null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Payment already initiated"
            );
        }

        PaymentRecord paymentRecord = new PaymentRecord();

        paymentRecord.setAmount(request.getAmount());

        paymentRecord.setPaymentMethod(
                request.getPaymentMethod()
        );

        paymentRecord.setShipperConfirmed(true);

        paymentRecord.setShipperConfirmedAt(
                LocalDateTime.now()
        );

        paymentRecord.setNote(request.getNote());
        paymentRecord.setCurrency(Currency.getInstance(request.getCurrencyCode()));
        paymentRecord.setShipment(shipment);

        shipment.setPaymentRecord(paymentRecord);
        shipment.setStatus(ShipmentStatus.PAYMENT_PENDING);

        ShipmentEvent shipmentEvent = new ShipmentEvent();
        shipmentEvent.setEventTimestamp(LocalDateTime.now());
        shipmentEvent.setDescription("Payment initiated");
        shipmentEvent.setLocation(shipment.getDestination());
        shipmentEvent.setShipmentStatus(ShipmentStatus.PAYMENT_PENDING);

        shipment.addShipmentEvent(shipmentEvent);
    }

    @Transactional
    public void confirmPayment(Long shipmentId, @CurrentUser CustomUserPrincipal user) {
        CarrierCompany carrierCompany = carrierCompanyRepository.findByAuthenticationEmail(user.getUsername()).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Carrier company not found for user: " + user.getUsername())
        );

        Shipment shipment = shipmentRepository.findById(shipmentId).orElseThrow(
                ()-> new ResponseStatusException(HttpStatus.NOT_FOUND, "Shipment with id "+shipmentId+" not found")
        );

        if (shipment.getAssignedCarrier() == null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Shipment has no assigned carrier"
            );
        }

        if(!shipment.getAssignedCarrier().getId().equals(carrierCompany.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Carrier not assigned to this shipment");
        }

        PaymentRecord paymentRecord = shipment.getPaymentRecord();
        validatePaymentRecord(paymentRecord);

        paymentRecord.setCarrierConfirmed(true);
        paymentRecord.setCarrierConfirmedAt(LocalDateTime.now());
        shipment.setStatus(ShipmentStatus.COMPLETED);
        shipment.setCompletedAt(LocalDateTime.now());
        paymentRecord.setShipment(shipment);

        ShipmentEvent shipmentEvent = createCompletionEvent(shipment.getDestination());
        shipmentEvent.setShipment(shipment);

        shipment.addShipmentEvent(shipmentEvent);
    }


    private void validatePaymentRecord(PaymentRecord paymentRecord) {
        if(paymentRecord == null){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Payment is not initiated for this shipment");
        }

        if (!paymentRecord.isShipperConfirmed()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Payment not initiated by shipper"
            );
        }

        if(paymentRecord.isCarrierConfirmed()){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Payment is already confirmed by carrier");
        }
    }

    private ShipmentEvent createCompletionEvent(String location) {
        ShipmentEvent shipmentEvent = new ShipmentEvent();
        shipmentEvent.setShipmentStatus(ShipmentStatus.COMPLETED);
        shipmentEvent.setDescription("Payment confirmed by carrier. Shipment completed");
        shipmentEvent.setLocation(location);
        shipmentEvent.setEventTimestamp(LocalDateTime.now());
        return shipmentEvent;
    }


}
