package com.memilogistics.shipmentservice.service;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.*;
import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.entity.ShipmentEvent;
import com.memilogistics.shipmentservice.entity.ShipmentOffer;
import com.memilogistics.shipmentservice.entity.ShipperProfile;
import com.memilogistics.shipmentservice.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.carriercompany.repository.CarrierCompanyRepository;
import com.memilogistics.shipmentservice.repository.ShipmentRepository;
import com.memilogistics.shipmentservice.shipperprofile.repository.ShipperProfileRepository;
import com.memilogistics.shipmentservice.mapper.ShipmentMapper;
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
    private final ShipperProfileRepository shipperProfileRepository;
    private final CarrierCompanyRepository carrierCompanyRepository;
    private final ShipmentMapper shipmentMapper;

    public CreateShipmentResponse createShipment(@CurrentUser CustomUserPrincipal user, CreateShipmentRequest request) {
        ShipperProfile shipper = shipperProfileRepository.findByAuthenticationEmail(user.getUsername())
                .orElseThrow(
                        ()-> new ResponseStatusException(HttpStatus.NOT_FOUND, "Shipper profile not found for user: " + user.getUsername())
                );

        Shipment shipment = new Shipment();
        shipment.setShipper(shipper);
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
        var shipments = shipmentRepository.findAllByFragile(fragile, pageable).orElse(List.of());
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
        var email = user.getUsername();
        Pageable pageable = PageRequest.of(Math.max(page, 0), Math.max(size, 1));

        return shipmentRepository.findByShipperAuthenticationEmail(email, pageable)
                .map(shipmentMapper::toResponse);
    }

    public Page<ShipmentResponse> findCurrentUserShipmentsByStatus(
            @CurrentUser CustomUserPrincipal user,
            ShipmentStatus status,
            int page,
            int size
    ){
        var email = user.getUsername();
        Pageable pageable = PageRequest.of(Math.max(page, 0), Math.max(size, 1));
        Page<Shipment> shipments = shipmentRepository.findByShipperAuthenticationEmailAndStatus(email, status, pageable);

        return shipments.map(shipmentMapper::toResponse);
    }

    @Transactional
    public Shipment updateShipment(Long id, UpdateShipmentRequest update) {
        if (update == null) {
            throw new IllegalArgumentException("Shipment update data is required");
        }
        Shipment existing = getShipment(id);

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

    public void deleteShipment(Long id) {
        var shipment = shipmentRepository.findById(id)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "Shipment not found with id: " + id
                        )
                );

        if (shipment.getStatus() != ShipmentStatus.PENDING
                && shipment.getStatus() != ShipmentStatus.ACCEPTED) {
            throw new IllegalArgumentException(
                    "Only shipments with PENDING or ACCEPTED status can be deleted"
            );
        }

        shipmentRepository.delete(shipment);

    }

    public void deleteShipmentByTrackingNumber(String trackingNumber) {
        shipmentRepository.deleteByTrackingNumber(trackingNumber);
    }

    public DashboardInformation getDashboardInformation() {
        return new DashboardInformation(
                shipmentRepository.countByStatus(ShipmentStatus.PENDING),
                shipmentRepository.countByStatus(ShipmentStatus.COMPLETED),
                shipmentRepository.countByFragile(true),
                shipmentRepository.countByFragile(false),
                shipperProfileRepository.count(),
                carrierCompanyRepository.count(),
                carrierCompanyRepository.count() + shipperProfileRepository.count(),
                shipmentRepository.count()
                );
    }

    private String generateTrackingNumber() {
        return "TRK-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12).toUpperCase();
    }
}
