package com.memilogistics.shipmentservice.carriercompany.repository;

import com.memilogistics.shipmentservice.carriercompany.entity.CarrierCompany;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CarrierCompanyRepository extends JpaRepository<CarrierCompany, Long> {
     Optional<CarrierCompany> findByAuthenticationEmail(String authenticationEmail);
}
