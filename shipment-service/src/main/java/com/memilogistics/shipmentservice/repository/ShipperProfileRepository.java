package com.memilogistics.shipmentservice.repository;

import com.memilogistics.shipmentservice.entity.CarrierCompany;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ShipperProfileRepository extends JpaRepository<CarrierCompany, Long> {
}
