package com.memilogistics.shipmentservice.repository;

import com.memilogistics.shipmentservice.entity.DeliveryConfirmation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PaymentRecordRepository extends JpaRepository<DeliveryConfirmation, Long> {

}
