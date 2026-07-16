package com.memilogistics.shipmentservice.companyprofile.service;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.companyprofile.dto.CompanyProfileResponse;
import com.memilogistics.shipmentservice.companyprofile.dto.CreateCompanyProfileRequest;
import com.memilogistics.shipmentservice.shipment.dto.ShipmentResponse;
import com.memilogistics.shipmentservice.companyprofile.dto.UpdateCompanyProfileRequest;
import com.memilogistics.shipmentservice.address.entity.Address;
import com.memilogistics.shipmentservice.companyprofile.entity.CompanyProfile;
import com.memilogistics.shipmentservice.common.mapper.ProfileMapper;
import com.memilogistics.shipmentservice.shipment.mapper.ShipmentMapper;
import com.memilogistics.shipmentservice.address.repository.AddressRepository;
import com.memilogistics.shipmentservice.companyprofile.repository.CompanyProfileRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CompanyProfileService {
    private final CompanyProfileRepository companyProfileRepository;
    private final AddressRepository addressRepository;
    private final ProfileMapper profileMapper;
    private final ShipmentMapper shipmentMapper;

    @Transactional
    public CompanyProfileResponse createCompanyProfile(@CurrentUser CustomUserPrincipal user,
                                                       CreateCompanyProfileRequest request) {
        if (user == null || user.getId() == null || user.getId().isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User context is required");
        }
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Company profile data is required");
        }

        companyProfileRepository.findByAuthenticationId(user.getId()).ifPresent(existing -> {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Company profile already exists");
        });

        Address address = buildAddress(request);
        addressRepository.save(address);

        CompanyProfile company = new CompanyProfile();
        company.setAuthenticationId(user.getId());
        company.setCompanyName(request.getCompanyName());
        company.setCompanyEmail(request.getCompanyEmail());
        company.setAddress(address);

        var companyProfile = companyProfileRepository.save(company);
        return profileMapper.toCompanyProfileResponse(companyProfile);
    }

    @Transactional
    public CompanyProfileResponse updateCompanyProfile(@CurrentUser CustomUserPrincipal user,
                                                              UpdateCompanyProfileRequest request) {
        if (user == null || user.getId() == null || user.getId().isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User context is required");
        }
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Company profile update data is required");
        }

        CompanyProfile company = companyProfileRepository.findByAuthenticationId(user.getId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Company profile not found"));

        if (request.getCompanyName() != null && !request.getCompanyName().isBlank()) {
            company.setCompanyName(request.getCompanyName());
        }
        if (request.getCompanyEmail() != null && !request.getCompanyEmail().isBlank()) {
            company.setCompanyEmail(request.getCompanyEmail());
        }

        if (hasAddressUpdate(request)) {
            Address address = company.getAddress();
            if (address == null) {
                address = new Address();
            }
            applyAddressUpdate(address, request);
            addressRepository.save(address);
            company.setAddress(address);
        }

        var companyProfile = companyProfileRepository.save(company);
        return profileMapper.toCompanyProfileResponse(companyProfile);
    }

    public CompanyProfileResponse getCompanyProfile(@CurrentUser CustomUserPrincipal user){
        var profile = companyProfileRepository.findByAuthenticationId(user.getId()).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Company profile not found")
        );

        return profileMapper.toCompanyProfileResponse(profile);
    }

    public CompanyProfileResponse getCompanyProfile(Long carrierCompanyId) {
        var company = companyProfileRepository.findById(carrierCompanyId).orElseThrow(
                ()-> new ResponseStatusException(HttpStatus.NOT_FOUND, "Carrier company not found with id: " + carrierCompanyId)
        );
        return profileMapper.toCompanyProfileResponse(company);
    }

    public List<ShipmentResponse> getAssignedShipments(
            @CurrentUser CustomUserPrincipal user
    ) {
        var carrier = companyProfileRepository.findByAuthenticationId(user.getId()).orElseThrow(
                ()-> new ResponseStatusException(HttpStatus.NOT_FOUND, "Carrier company not found")
        );
        var shipments = carrier.getAssignedShipments();
        return shipmentMapper.toResponseList(shipments);
    }

    public List<ShipmentResponse> getAssignedShipments(Long carrierId){
        var carrier = companyProfileRepository.findById(carrierId).orElseThrow(
                ()-> new ResponseStatusException(HttpStatus.NOT_FOUND, "Carrier company not found")
        );
        var shipments = carrier.getAssignedShipments();
        return shipmentMapper.toResponseList(shipments);
    }



    private Address buildAddress(CreateCompanyProfileRequest request) {
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

    private boolean hasAddressUpdate(UpdateCompanyProfileRequest request) {
        return (request.getStreet() != null && !request.getStreet().isBlank())
                || (request.getCity() != null && !request.getCity().isBlank())
                || (request.getState() != null && !request.getState().isBlank())
                || (request.getZip() != null && !request.getZip().isBlank())
                || (request.getCountry() != null && !request.getCountry().isBlank())
                || (request.getPhoneNumber() != null && !request.getPhoneNumber().isBlank());
    }

    private void applyAddressUpdate(Address address, UpdateCompanyProfileRequest request) {
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
