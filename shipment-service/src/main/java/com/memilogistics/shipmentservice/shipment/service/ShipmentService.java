package com.memilogistics.shipmentservice.shipment.service;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dashboard.DashboardInformation;
import com.memilogistics.shipmentservice.shipment.dto.CreateShipmentRequest;
import com.memilogistics.shipmentservice.shipment.dto.CreateShipmentResponse;
import com.memilogistics.shipmentservice.shipment.dto.ShipmentResponse;
import com.memilogistics.shipmentservice.shipment.dto.UpdateShipmentRequest;
import com.memilogistics.shipmentservice.shipment.entity.Shipment;
import com.memilogistics.shipmentservice.shipment.entity.ShipmentEvent;
import com.memilogistics.shipmentservice.shipment.entity.ShipmentOffer;
import com.memilogistics.shipmentservice.userprofile.entity.UserProfile;
import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.companyprofile.repository.CompanyProfileRepository;
import com.memilogistics.shipmentservice.shipment.repository.ShipmentRepository;
import com.memilogistics.shipmentservice.userprofile.repository.UserProfileRepository;
import com.memilogistics.shipmentservice.shipment.mapper.ShipmentMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ShipmentService {
    private final ShipmentRepository shipmentRepository;
    private final UserProfileRepository userProfileRepository;
    private final CompanyProfileRepository companyProfileRepository;
    private final ShipmentMapper shipmentMapper;

    public CreateShipmentResponse createShipment(@CurrentUser CustomUserPrincipal user, CreateShipmentRequest request) {
        UserProfile userProfile = userProfileRepository.findByAuthenticationId(user.getId())
                .orElseThrow(
                        ()-> new ResponseStatusException(HttpStatus.NOT_FOUND, "User profile not found for user: " + user.getId())
                );


        Shipment shipment = new Shipment();
        shipment.setShipper(userProfile);
        shipment.setShipmentItem(request.getShipmentItem());
        shipment.setTrackingNumber(generateTrackingNumber());
        shipment.setOrigin(request.getOrigin());
        shipment.setDestination(request.getDestination());
        shipment.setWeightKg(request.getWeightKg());
        shipment.setEstimatedDeliveryDate(request.getDeliveryDate());
        shipment.setFragile(request.isFragile());
        shipment.setDescription(request.getDescription());

        shipmentRepository.findByTrackingNumber(shipment.getTrackingNumber())
                .ifPresent(existing -> {
                    throw new IllegalArgumentException("Tracking number already exists");
                });

        ShipmentEvent event = new ShipmentEvent();
        event.setShipment(shipment);
        event.setShipmentStatus(ShipmentStatus.PENDING);
        event.setLocation(request.getOrigin());
        event.setEventTimestamp(shipment.getCreatedAt() != null ? shipment.getCreatedAt() : LocalDateTime.now());
        shipment.getShipmentEvents().add(event);

        Shipment saved = shipmentRepository.save(shipment);
        return shipmentMapper.toCreateShipmentResponse(saved);
    }

    public Shipment getShipment(Long id) {
        return shipmentRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Shipment not found with id: " + id));
    }

    public List<ShipmentOffer> getShipmentOffers(Long id) {
        Shipment shipment = getShipment(id);
        return shipment.getShipmentOffers();
    }

    public ShipmentResponse getShipmentByTrackingNumber(String trackingNumber) {
        if (trackingNumber == null || trackingNumber.isBlank()) {
            throw new IllegalArgumentException("Tracking number is required");
        }
        var shipment = shipmentRepository.findByTrackingNumber(trackingNumber)
                .orElseThrow(() -> new IllegalArgumentException("Shipment not found with tracking number: " + trackingNumber));
        return shipmentMapper.toResponse(shipment);
    }

    public List<ShipmentResponse> listShipments(int page, int size) {
        Pageable pageable = PageRequest.of(Math.max(page, 0), Math.max(size, 1));
        var shipments = shipmentRepository.findAll(pageable).getContent();
        return shipmentMapper.toResponseList(shipments);
    }

    public List<ShipmentResponse> listShipmentsByFragile(boolean fragile, int page, int size) {
        Pageable pageable = PageRequest.of(Math.max(page, 0), Math.max(size, 1));
        var shipments = shipmentRepository.findAllByFragile(fragile, pageable);
        return shipmentMapper.toResponseList(shipments);
    }

    public List<ShipmentResponse> listShipmentsByDestination(String destination, int page, int size) {
        Pageable pageable = PageRequest.of(Math.max(page, 0), Math.max(size, 1));
        var shipments = shipmentRepository.findAllByDestination(destination, pageable);
        return shipmentMapper.toResponseList(shipments);
    }

    public List<ShipmentResponse> listShipmentsByOrigin(String origin, int page, int size) {
        Pageable pageable = PageRequest.of(Math.max(page, 0), Math.max(size, 1));
        var shipments = shipmentRepository.findAllByOrigin(origin, pageable);
        return shipmentMapper.toResponseList(shipments);
    }

    public Page<ShipmentResponse> findCurrentUserShipments(
            @CurrentUser CustomUserPrincipal user,
            int page,
            int size
    ){

        Pageable pageable = PageRequest.of(Math.max(page, 0), Math.max(size, 1));

        return shipmentRepository.findByShipperAuthenticationId(user.getId(), pageable)
                .map(shipmentMapper::toResponse);
    }

    public Page<ShipmentResponse> findCurrentUserShipmentsByStatus(
            @CurrentUser CustomUserPrincipal user,
            ShipmentStatus status,
            int page,
            int size
    ){
        Pageable pageable = PageRequest.of(Math.max(page, 0), Math.max(size, 1));
        Page<Shipment> shipments = shipmentRepository
                .findByShipperAuthenticationIdAndStatus(user.getId(), status, pageable);

        return shipments.map(shipmentMapper::toResponse);
    }

    @Transactional
    public Shipment updateShipment(Long id, UpdateShipmentRequest update, CustomUserPrincipal user) {
        if (update == null) {
            throw new IllegalArgumentException("Shipment update data is required");
        }
        Shipment existing = getShipment(id);

        if(!existing.getShipper().getAuthenticationId().equals(user.getId())){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You are not authorized to update this shipment");
        }

        if (update.getOrigin() != null && !update.getOrigin().isBlank()) {
            existing.setOrigin(update.getOrigin());
        }
        if (update.getDestination() != null && !update.getDestination().isBlank()) {
            existing.setDestination(update.getDestination());
        }
        if (update.getWeightKg() != null) {
            existing.setWeightKg(update.getWeightKg());
        }

        if (update.getDeliveryDate() != null) {
            existing.setEstimatedDeliveryDate(update.getDeliveryDate());
        }

        if(update.getDescription() != null) {
            existing.setDescription(update.getDescription());
        }

        return shipmentRepository.save(existing);
    }

    public void deleteShipment(Long id, CustomUserPrincipal user) {
        var shipment = shipmentRepository.findById(id)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "Shipment not found with id: " + id
                        )
                );

        if(!user.getId().equals(shipment.getShipper().getAuthenticationId())){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You are not authorized to delete this shipment");
        }

        if (shipment.getStatus() != ShipmentStatus.PENDING
                && shipment.getStatus() != ShipmentStatus.ACCEPTED) {
            throw new IllegalArgumentException(
                    "Only shipments with PENDING or ACCEPTED status can be deleted"
            );
        }

        shipmentRepository.delete(shipment);

    }

    public void deleteShipmentByTrackingNumber(String trackingNumber, CustomUserPrincipal user) {
        var shipment = shipmentRepository.findByTrackingNumber(trackingNumber).orElseThrow(
                ()-> new ResponseStatusException(HttpStatus.NOT_FOUND, "Shipment not found with trackingNumber: " + trackingNumber)
        );
        if(!user.getId().equals(shipment.getShipper().getAuthenticationId())){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You are not authorized to delete this shipment");
        }
        shipmentRepository.deleteByTrackingNumber(trackingNumber);
    }
    

    private String generateTrackingNumber() {
        return "TRK-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12).toUpperCase();
    }
}
