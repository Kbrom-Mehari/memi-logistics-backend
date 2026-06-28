package com.memilogistics.shipmentservice.shipment.repository;

import com.memilogistics.shipmentservice.shipment.entity.ShipmentEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ShipmentEventRepository extends JpaRepository<ShipmentEvent, Long> {

}
