package com.memilogistics.shipmentservice.shipperprofile.service;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.shipperprofile.dto.CreateShipperProfileRequest;
import com.memilogistics.shipmentservice.address.entity.Address;
import com.memilogistics.shipmentservice.shipperprofile.entity.ShipperProfile;
import com.memilogistics.shipmentservice.address.repository.AddressRepository;
import com.memilogistics.shipmentservice.common.mapper.ProfileMapper;
import com.memilogistics.shipmentservice.shipperprofile.dto.UpdateShipperProfileRequest;
import com.memilogistics.shipmentservice.shipperprofile.dto.ShipperProfileResponse;
import com.memilogistics.shipmentservice.shipperprofile.repository.ShipperProfileRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class ShipperProfileService {
    private final ShipperProfileRepository shipperProfileRepository;
    private final AddressRepository addressRepository;
    private final ProfileMapper profileMapper;

    @Transactional
    public ShipperProfileResponse createShipperProfile(@CurrentUser CustomUserPrincipal user,
                                                       CreateShipperProfileRequest request) {
        if (user == null || user.getUsername() == null || user.getUsername().isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User context is required");
        }
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Shipper profile data is required");
        }

        shipperProfileRepository.findByAuthenticationEmail(user.getUsername()).ifPresent(existing -> {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Shipper profile already exists");
        });

        Address address = buildAddress(request);
        addressRepository.save(address);

        ShipperProfile profile = new ShipperProfile();
        profile.setAuthenticationEmail(user.getUsername());
        profile.setFirstName(request.getFirstName());
        profile.setLastName(request.getLastName());
        profile.setCompanyName(request.getCompanyName());
        profile.setBusinessName(request.getBusinessName());
        profile.setAddress(address);

        var shipperProfile = shipperProfileRepository.save(profile);
        return profileMapper.toShipperProfileResponse(shipperProfile);
    }

    @Transactional
    public ShipperProfileResponse updateShipperProfile(@CurrentUser CustomUserPrincipal user,
                                               UpdateShipperProfileRequest request) {
        if (user == null || user.getUsername() == null || user.getUsername().isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User context is required");
        }
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Shipper profile update data is required");
        }

        ShipperProfile profile = shipperProfileRepository.findByAuthenticationEmail(user.getUsername())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Shipper profile not found"));

        if (request.getFirstName() != null && !request.getFirstName().isBlank()) {
            profile.setFirstName(request.getFirstName());
        }
        if (request.getLastName() != null && !request.getLastName().isBlank()) {
            profile.setLastName(request.getLastName());
        }
        if (request.getCompanyName() != null && !request.getCompanyName().isBlank()) {
            profile.setCompanyName(request.getCompanyName());
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

        var shipperProfile = shipperProfileRepository.save(profile);
        return profileMapper.toShipperProfileResponse(shipperProfile);
    }

    public ShipperProfileResponse getShipperProfile(@CurrentUser CustomUserPrincipal user){
        if (user == null || user.getUsername() == null || user.getUsername().isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User context is required");
        }
        ShipperProfile profile = shipperProfileRepository.findByAuthenticationEmail(user.getUsername()).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Shipper profile not found")
        );
        return profileMapper.toShipperProfileResponse(profile);
    }

    public ShipperProfileResponse getShipperProfile(Long shipperId){
        var profile = shipperProfileRepository.findById(shipperId).orElseThrow(
                ()-> new ResponseStatusException(HttpStatus.NOT_FOUND, "Shipper profile not found with id: " + shipperId)
        );
        return profileMapper.toShipperProfileResponse(profile);
    }

    private Address buildAddress(CreateShipperProfileRequest request) {
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

    private boolean hasAddressUpdate(UpdateShipperProfileRequest request) {
        return (request.getStreet() != null && !request.getStreet().isBlank())
                || (request.getCity() != null && !request.getCity().isBlank())
                || (request.getState() != null && !request.getState().isBlank())
                || (request.getZip() != null && !request.getZip().isBlank())
                || (request.getCountry() != null && !request.getCountry().isBlank())
                || (request.getPhoneNumber() != null && !request.getPhoneNumber().isBlank());
    }

    private void applyAddressUpdate(Address address, UpdateShipperProfileRequest request) {
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
