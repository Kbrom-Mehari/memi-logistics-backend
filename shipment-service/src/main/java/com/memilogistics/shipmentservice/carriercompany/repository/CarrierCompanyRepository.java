package com.memilogistics.shipmentservice.repository;

import com.memilogistics.shipmentservice.entity.CarrierCompany;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CarrierCompanyRepository extends JpaRepository<CarrierCompany, Long> {
     Optional<CarrierCompany> findByAuthenticationEmail(String authenticationEmail);
}
