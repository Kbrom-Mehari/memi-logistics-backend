package com.memilogistics.shipmentservice.repository;

import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.enums.ShipmentStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ShipmentRepository extends JpaRepository<Shipment, Long> {
    Optional<Shipment> findByTrackingNumber(String trackingNumber);
    Optional<List<Shipment>> findAllByFragile(boolean fragile, Pageable pageable);
    List<Shipment> findAllByDestination(String destination, Pageable pageable);
    List<Shipment> findAllByOrigin(String origin, Pageable pageable);
    void deleteByTrackingNumber(String trackingNumber);
    Long countByFragile(boolean fragile);
    Long countByOrigin(String origin);
    Long countByStatus(ShipmentStatus status);
    Page<Shipment> findByShipperAuthenticationEmailAndStatus(
            String email,
            ShipmentStatus status,
            Pageable pageable
    );
    Page<Shipment> findByShipperAuthenticationEmail(String email, Pageable pageable);

}
