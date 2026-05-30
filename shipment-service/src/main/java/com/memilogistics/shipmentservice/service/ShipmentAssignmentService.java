package com.memilogistics.shipmentservice.service;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
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
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class ShipmentAssignmentService {
    private final ShipmentOfferRepository shipmentOfferRepository;
    private final ShipmentRepository shipmentRepository;
    private final CarrierCompanyRepository carrierCompanyRepository;

    @Transactional
    public void offerShipment(Long shipmentId, @CurrentUser CustomUserPrincipal user, BigDecimal price) {
        ShipmentOffer shipmentOffer = new ShipmentOffer();
        Shipment shipment = shipmentRepository.findById(shipmentId).
                orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "shipment with id " + shipmentId + " not found"
                ));

        CarrierCompany carrierCompany = carrierCompanyRepository.findByAuthenticationEmail(user.getUsername())
                .orElseThrow(()-> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "carrier company not found"
                ));

        shipmentOffer.setPrice(price);
        shipmentOffer.setCreatedAt(LocalDateTime.now());
        shipmentOffer.setShipment(shipment);
        shipmentOffer.setCarrierCompany(carrierCompany);

        shipment.getShipmentOffers().add(shipmentOffer);
        shipment.setStatus(ShipmentStatus.ACCEPTED);
    }

    @Transactional
    public void cancelShipmentOffer(Long shipmentOfferId, @CurrentUser CustomUserPrincipal user){
        ShipmentOffer shipmentOffer = shipmentOfferRepository.findById(shipmentOfferId)
                .orElseThrow(
                        ()-> new ResponseStatusException(
                                HttpStatus.NOT_FOUND, "offer with id " + shipmentOfferId + " not found"
                        )
                );

        CarrierCompany carrierCompany = carrierCompanyRepository.findByAuthenticationEmail(user.getUsername())
                .orElseThrow(
                        ()-> new ResponseStatusException(
                                HttpStatus.NOT_FOUND, "carrier company not found"
                        )
                );

        if(!shipmentOffer.getCarrierCompany().getId().equals(carrierCompany.getId())){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "cannot cancel another carrier's offer");
        }

        var shipment = shipmentOffer.getShipment();

        carrierCompany.getOfferedShipments().remove(shipmentOffer);
        shipment.getShipmentOffers().remove(shipmentOffer);

        if(shipment.getShipmentOffers().isEmpty()){
            shipment.setStatus(ShipmentStatus.PENDING);
        }

        shipmentRepository.save(shipment);
    }

    @Transactional
    public void assignCarrier(Long shipmentId, Long carrierId) {
        Shipment shipment = shipmentRepository.findById(shipmentId)
                .orElseThrow(
                        ()-> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Shipment with id " + shipmentId + " not found"
                        )
                );
        CarrierCompany carrierCompany = carrierCompanyRepository.findById(carrierId)
                .orElseThrow(
                        ()-> new ResponseStatusException(
                                HttpStatus.NOT_FOUND, "carrier company with id " + carrierId + " not found"
                        )
                );

        shipment.setAssignedCarrier(carrierCompany);
        shipment.setStatus(ShipmentStatus.ASSIGNED);
        shipmentRepository.save(shipment);
    }

}
