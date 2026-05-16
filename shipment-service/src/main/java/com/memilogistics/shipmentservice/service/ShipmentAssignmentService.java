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
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class ShipmentAssignmentService {
    private final ShipmentOfferRepository shipmentOfferRepository;
    private final ShipmentRepository shipmentRepository;
    private final CarrierCompanyRepository carrierCompanyRepository;

    @Transactional
    public void offerShipment(ShipmentOfferRequest request) {
        ShipmentOffer shipmentOffer = new ShipmentOffer();
        Shipment shipment = shipmentRepository.findById(request.getShipmentId()).
                orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "shipment with id " + request.getShipmentId() + " not found"
                ));

        CarrierCompany carrierCompany = carrierCompanyRepository.findById(request.getCarrierCompanyId())
                .orElseThrow(()-> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "carrier company with id " + request.getCarrierCompanyId() + " not found"
                ));

        shipmentOffer.setPrice(request.getPrice());
        shipmentOffer.setCreatedAt(LocalDateTime.now());
        shipmentOffer.setShipment(shipment);
        shipmentOffer.setCarrierCompany(carrierCompany);

        shipment.getShipmentOffers().add(shipmentOffer);
        shipment.setStatus(ShipmentStatus.ACCEPTED);

        shipmentRepository.save(shipment);
        shipmentOfferRepository.save(shipmentOffer);
    }

    @Transactional
    public void cancelShipmentOffer(CancelShipmentOfferRequest request){
        ShipmentOffer shipmentOffer = shipmentOfferRepository.findById(request.getShipmentOfferId())
                .orElseThrow(
                        ()-> new ResponseStatusException(
                                HttpStatus.NOT_FOUND, "offer with id " + request.getShipmentOfferId() + " not found"
                        )
                );
        CarrierCompany carrierCompany = carrierCompanyRepository.findById(request.getCarrierId())
                .orElseThrow(
                        ()-> new ResponseStatusException(
                                HttpStatus.NOT_FOUND, "carrier company with id " + request.getCarrierId() + " not found"
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
    public void assignCarrier(AssignCarrierRequest request){
        Shipment shipment = shipmentRepository.findById(request.getShipmentId())
                .orElseThrow(
                        ()-> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Shipment with id " + request.getShipmentId() + " not found"
                        )
                );
        CarrierCompany carrierCompany = carrierCompanyRepository.findById(request.getCarrierId())
                .orElseThrow(
                        ()-> new ResponseStatusException(
                                HttpStatus.NOT_FOUND, "carrier company with id " + request.getCarrierId() + " not found"
                        )
                );

        shipment.setAssignedCarrier(carrierCompany);
        shipment.setStatus(ShipmentStatus.ASSIGNED);
        shipmentRepository.save(shipment);
    }

}
