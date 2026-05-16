package com.memilogistics.shipmentservice.repository;

import com.memilogistics.shipmentservice.entity.ShipmentEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ShipmentEventRepository extends JpaRepository<ShipmentEvent, Long> {

}
