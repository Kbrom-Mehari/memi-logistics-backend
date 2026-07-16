package com.memilogistics.shipmentservice.shipment.service;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.companyprofile.entity.CompanyProfile;
import com.memilogistics.shipmentservice.shipment.dto.ShipmentOfferRequest;
import com.memilogistics.shipmentservice.shipment.entity.Shipment;
import com.memilogistics.shipmentservice.shipment.entity.ShipmentOffer;
import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.companyprofile.repository.CompanyProfileRepository;
import com.memilogistics.shipmentservice.shipment.repository.ShipmentOfferRepository;
import com.memilogistics.shipmentservice.shipment.repository.ShipmentRepository;
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
    private final CompanyProfileRepository companyProfileRepository;

    @Transactional
    public void offerShipment(@CurrentUser CustomUserPrincipal user, ShipmentOfferRequest request) {
        ShipmentOffer shipmentOffer = new ShipmentOffer();
        Shipment shipment = shipmentRepository.findById(request.getShipmentId()).
                orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "shipment with id " + request.getShipmentId() + " not found"
                ));
        if(shipment.getShipper().getAuthenticationId().equals(user.getId())){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You cannot bid on your own shipment");
        }

        CompanyProfile companyProfile = companyProfileRepository.findByAuthenticationId(user.getId())
                .orElseThrow(()-> new ResponseStatusException(
                        HttpStatus.FORBIDDEN, "You must complete your company profile before offering a shipment."
                ));

        shipmentOffer.setPrice(request.getPrice());
        shipmentOffer.setCurrencyCode(request.getCurrencyCode());
        shipmentOffer.setCreatedAt(LocalDateTime.now());
        shipmentOffer.setShipment(shipment);
        shipmentOffer.setCarrierCompany(companyProfile);

        shipment.getShipmentOffers().add(shipmentOffer);
        // maintain bidirectional relation on company profile as well
        companyProfile.getOfferedShipments().add(shipmentOffer);

        shipment.setStatus(ShipmentStatus.ACCEPTED);

        // persist the new offer and updated shipment
        shipmentOfferRepository.save(shipmentOffer);
        shipmentRepository.save(shipment);
    }

    @Transactional
    public void cancelShipmentOffer(Long shipmentOfferId, @CurrentUser CustomUserPrincipal user){
        ShipmentOffer shipmentOffer = shipmentOfferRepository.findById(shipmentOfferId)
                .orElseThrow(
                        ()-> new ResponseStatusException(
                                HttpStatus.NOT_FOUND, "offer with id " + shipmentOfferId + " not found"
                        )
                );

        CompanyProfile companyProfile = companyProfileRepository.findByAuthenticationId(user.getId())
                .orElseThrow(
                        ()-> new ResponseStatusException(
                                HttpStatus.NOT_FOUND, "carrier company not found"
                        )
                );

        if(!shipmentOffer.getCarrierCompany().getCompanyProfileId().equals(companyProfile.getCompanyProfileId())){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "cannot cancel another carrier's offer");
        }

        var shipment = shipmentOffer.getShipment();

        companyProfile.getOfferedShipments().remove(shipmentOffer);
        shipment.getShipmentOffers().remove(shipmentOffer);

        if(shipment.getShipmentOffers().isEmpty()){
            shipment.setStatus(ShipmentStatus.PENDING);
        }

        shipmentRepository.save(shipment);
    }

    @Transactional
    public void assignCarrier(Long shipmentId, Long carrierId) {
        Shipment shipment = shipmentRepository.findById(shipmentId)
                .orElseThrow( ()-> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Shipment with id " + shipmentId + " not found"
                        )
                );
        CompanyProfile carrierCompany = companyProfileRepository.findById(carrierId)
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
