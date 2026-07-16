package com.memilogistics.shipmentservice.userprofile.repository;

import com.memilogistics.shipmentservice.userprofile.entity.UserProfile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserProfileRepository extends JpaRepository<UserProfile, Long> {
    Optional<UserProfile> findByAuthenticationId(String id);
    Optional<UserProfile> findByProfileId(Long profileId);
}
