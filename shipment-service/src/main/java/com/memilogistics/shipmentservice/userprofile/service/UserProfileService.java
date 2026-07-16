package com.memilogistics.shipmentservice.userprofile.service;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.userprofile.dto.CreateUserProfileRequest;
import com.memilogistics.shipmentservice.address.entity.Address;
import com.memilogistics.shipmentservice.userprofile.entity.UserProfile;
import com.memilogistics.shipmentservice.address.repository.AddressRepository;
import com.memilogistics.shipmentservice.common.mapper.ProfileMapper;
import com.memilogistics.shipmentservice.userprofile.dto.UpdateUserProfileRequest;
import com.memilogistics.shipmentservice.userprofile.dto.UserProfileResponse;
import com.memilogistics.shipmentservice.userprofile.repository.UserProfileRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class UserProfileService {
    private final UserProfileRepository userProfileRepository;
    private final AddressRepository addressRepository;
    private final ProfileMapper profileMapper;

    @Transactional
    public UserProfileResponse createUserProfile(@CurrentUser CustomUserPrincipal user,
                                                 CreateUserProfileRequest request) {
        if (user == null || user.getId() == null || user.getId().isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User context is required");
        }
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User profile data is required");
        }

        userProfileRepository.findByAuthenticationId(user.getId()).ifPresent(existing -> {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "User profile already exists");
        });

        Address address = buildAddress(request);
        addressRepository.save(address);

        UserProfile profile = new UserProfile();

        profile.setAuthenticationId(user.getId());
        profile.setFirstName(request.getFirstName());
        profile.setLastName(request.getLastName());
        profile.setBusinessName(request.getBusinessName());
        profile.setAddress(address);

        return profileMapper.toUserProfileResponse(userProfileRepository.save(profile));
    }

    @Transactional
    public UserProfileResponse updateUserProfile(@CurrentUser CustomUserPrincipal user,
                                                    UpdateUserProfileRequest request) {
        if (user == null || user.getId() == null || user.getId().isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User context is required");
        }
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User profile update data is required");
        }

        UserProfile profile = userProfileRepository.findByAuthenticationId(user.getId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User profile not found"));

        if (request.getFirstName() != null && !request.getFirstName().isBlank()) {
            profile.setFirstName(request.getFirstName());
        }

        if (request.getLastName() != null && !request.getLastName().isBlank()) {
            profile.setLastName(request.getLastName());
        }

        if (request.getBusinessName() != null && !request.getBusinessName().isBlank()) {
            profile.setBusinessName(request.getBusinessName());
        }

        if (hasAddressUpdate(request)) {
            Address address = profile.getAddress();
            if (address == null) {
                address = new Address();
            }
            applyAddressUpdate(address, request);
            addressRepository.save(address);
            profile.setAddress(address);
        }

        var userProfile = userProfileRepository.save(profile);
        return profileMapper.toUserProfileResponse(userProfile);
    }

    public UserProfileResponse getUserProfile(@CurrentUser CustomUserPrincipal user){
        if (user == null || user.getId() == null || user.getId().isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User context is required");
        }
        UserProfile profile = userProfileRepository.findByAuthenticationId(user.getId()).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User profile not found")
        );
        return profileMapper.toUserProfileResponse(profile);
    }

    public UserProfileResponse getUserProfile(Long userProfileId) {
        var profile = userProfileRepository.findByProfileId(userProfileId).orElseThrow(
                ()-> new ResponseStatusException(HttpStatus.NOT_FOUND, "User profile not found with id: " + userProfileId)
        );
        return profileMapper.toUserProfileResponse(profile);
    }

    private Address buildAddress(CreateUserProfileRequest request) {
        Address address = new Address();
        address.setStreet(request.getStreet());
        address.setCity(request.getCity());
        address.setState(request.getState());
        address.setZip(request.getZip());
        if (request.getCountry() != null && !request.getCountry().isBlank()) {
            address.setCountry(request.getCountry());
        }
        address.setPhoneNumber(request.getPhoneNumber());
        return address;
    }

    private boolean hasAddressUpdate(UpdateUserProfileRequest request) {
        return (request.getStreet() != null && !request.getStreet().isBlank())
                || (request.getCity() != null && !request.getCity().isBlank())
                || (request.getState() != null && !request.getState().isBlank())
                || (request.getZip() != null && !request.getZip().isBlank())
                || (request.getCountry() != null && !request.getCountry().isBlank())
                || (request.getPhoneNumber() != null && !request.getPhoneNumber().isBlank());
    }

    private void applyAddressUpdate(Address address, UpdateUserProfileRequest request) {
        if (request.getStreet() != null && !request.getStreet().isBlank()) {
            address.setStreet(request.getStreet());
        }
        if (request.getCity() != null && !request.getCity().isBlank()) {
            address.setCity(request.getCity());
        }
        if (request.getState() != null && !request.getState().isBlank()) {
            address.setState(request.getState());
        }
        if (request.getZip() != null && !request.getZip().isBlank()) {
            address.setZip(request.getZip());
        }
        if (request.getCountry() != null && !request.getCountry().isBlank()) {
            address.setCountry(request.getCountry());
        }
        if (request.getPhoneNumber() != null && !request.getPhoneNumber().isBlank()) {
            address.setPhoneNumber(request.getPhoneNumber());
        }
    }
}
