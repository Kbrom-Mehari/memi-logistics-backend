package com.memilogistics.shipmentservice.shipperprofile.repository;

import com.memilogistics.shipmentservice.shipperprofile.entity.ShipperProfile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ShipperProfileRepository extends JpaRepository<ShipperProfile, Long> {
    Optional<ShipperProfile> findByAuthenticationEmail(String email);
}
