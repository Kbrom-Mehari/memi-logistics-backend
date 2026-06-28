package com.memilogistics.shipmentservice.repository;

import com.memilogistics.shipmentservice.entity.ShipmentOffer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ShipmentOfferRepository extends JpaRepository<ShipmentOffer, Long> {
     ShipmentOffer findByShipmentIdAndCarrierCompanyId(Long shipmentId, Long carrierCompanyId);
}
