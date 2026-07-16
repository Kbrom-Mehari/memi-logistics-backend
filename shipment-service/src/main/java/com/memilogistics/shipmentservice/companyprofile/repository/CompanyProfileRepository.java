package com.memilogistics.shipmentservice.companyprofile.repository;

import com.memilogistics.shipmentservice.companyprofile.entity.CompanyProfile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CompanyProfileRepository extends JpaRepository<CompanyProfile, Long> {
     Optional<CompanyProfile> findByAuthenticationId(String authenticationId);
     boolean  existsByAuthenticationId(String authenticationId);
}
