package com.memilogistics.shipmentservice.service;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.CreateShipmentRequest;
import com.memilogistics.shipmentservice.dto.DashboardInformation;
import com.memilogistics.shipmentservice.dto.UpdateShipmentRequest;
import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.entity.ShipmentEvent;
import com.memilogistics.shipmentservice.entity.ShipmentOffer;
import com.memilogistics.shipmentservice.entity.ShipperProfile;
import com.memilogistics.shipmentservice.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.repository.ShipmentRepository;
import com.memilogistics.shipmentservice.repository.ShipperProfileRepository;
import lombok.RequiredArgsConstructor;
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

    public Shipment createShipment(@CurrentUser CustomUserPrincipal user, CreateShipmentRequest request) {
        ShipperProfile shipper = shipperProfileRepository.findByEmail(user.getUsername())
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

        return shipmentRepository.save(shipment);
    }

    public Shipment getShipment(Long id) {
        return shipmentRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Shipment not found with id: " + id));
    }

    public List<ShipmentOffer> getShipmentOffers(Long id) {
        Shipment shipment = getShipment(id);
        return shipment.getShipmentOffers();
    }

    public Shipment getShipmentByTrackingNumber(String trackingNumber) {
        if (trackingNumber == null || trackingNumber.isBlank()) {
            throw new IllegalArgumentException("Tracking number is required");
        }
        return shipmentRepository.findByTrackingNumber(trackingNumber)
                .orElseThrow(() -> new IllegalArgumentException("Shipment not found with tracking number: " + trackingNumber));
    }

    public List<Shipment> listShipments(int page, int size) {
        Pageable pageable = PageRequest.of(Math.max(page, 0), Math.max(size, 1));
        return shipmentRepository.findAll(pageable).getContent();
    }

    public List<Shipment> listShipmentsByFragile(boolean fragile, int page, int size) {
        Pageable pageable = PageRequest.of(Math.max(page, 0), Math.max(size, 1));
        return shipmentRepository.findAllByFragile(fragile, pageable).orElse(List.of());
    }

    public List<Shipment> listShipmentsByDestination(String destination, int page, int size) {
        Pageable pageable = PageRequest.of(Math.max(page, 0), Math.max(size, 1));
        return shipmentRepository.findAllByDestination(destination, pageable);
    }

    public List<Shipment> listShipmentsByOrigin(String origin, int page, int size) {
        Pageable pageable = PageRequest.of(Math.max(page, 0), Math.max(size, 1));
        return shipmentRepository.findAllByOrigin(origin, pageable);
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
                shipmentRepository.countByStatus(ShipmentStatus.DELIVERED),
                shipmentRepository.countByFragile(true),
                shipmentRepository.countByFragile(false)
                );
    }

    private String generateTrackingNumber() {
        return "TRK-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12).toUpperCase();
    }
}
