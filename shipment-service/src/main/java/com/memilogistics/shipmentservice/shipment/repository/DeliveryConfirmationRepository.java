package com.memilogistics.shipmentservice.shipment.repository;

import com.memilogistics.shipmentservice.shipment.entity.DeliveryConfirmation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DeliveryConfirmationRepository extends JpaRepository<DeliveryConfirmation, Long> {

}
