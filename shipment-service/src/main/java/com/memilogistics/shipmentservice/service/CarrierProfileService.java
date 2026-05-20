package com.memilogistics.shipmentservice.service;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.CreateCarrierProfileRequest;
import com.memilogistics.shipmentservice.dto.UpdateCarrierProfileRequest;
import com.memilogistics.shipmentservice.entity.Address;
import com.memilogistics.shipmentservice.entity.CarrierCompany;
import com.memilogistics.shipmentservice.entity.ShipperProfile;
import com.memilogistics.shipmentservice.repository.AddressRepository;
import com.memilogistics.shipmentservice.repository.CarrierCompanyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class CarrierProfileService {
    private final CarrierCompanyRepository carrierCompanyRepository;
    private final AddressRepository addressRepository;

    @Transactional
    public CarrierCompany createCarrierCompanyProfile(@CurrentUser CustomUserPrincipal user,
                                                      CreateCarrierProfileRequest request) {
        if (user == null || user.getUsername() == null || user.getUsername().isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User context is required");
        }
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Carrier profile data is required");
        }

        carrierCompanyRepository.findByAuthenticationEmail(user.getUsername()).ifPresent(existing -> {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Carrier profile already exists");
        });

        Address address = buildAddress(request);
        addressRepository.save(address);

        CarrierCompany company = new CarrierCompany();
        company.setAuthenticationEmail(user.getUsername());
        company.setCompanyName(request.getCompanyName());
        company.setCompanyEmail(request.getCompanyEmail());
        company.setAddress(address);

        return carrierCompanyRepository.save(company);
    }

    @Transactional
    public CarrierCompany updateCarrierCompanyProfile(@CurrentUser CustomUserPrincipal user,
                                                      UpdateCarrierProfileRequest request) {
        if (user == null || user.getUsername() == null || user.getUsername().isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User context is required");
        }
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Carrier profile update data is required");
        }

        CarrierCompany company = carrierCompanyRepository.findByAuthenticationEmail(user.getUsername())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Carrier profile not found"));

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

        return carrierCompanyRepository.save(company);
    }

    public CarrierCompany getCarrierProfile(@CurrentUser CustomUserPrincipal user){
        return carrierCompanyRepository.findByAuthenticationEmail(user.getUsername()).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Carrier profile not found")
        );
    }

    private Address buildAddress(CreateCarrierProfileRequest request) {
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

    private boolean hasAddressUpdate(UpdateCarrierProfileRequest request) {
        return (request.getStreet() != null && !request.getStreet().isBlank())
                || (request.getCity() != null && !request.getCity().isBlank())
                || (request.getState() != null && !request.getState().isBlank())
                || (request.getZip() != null && !request.getZip().isBlank())
                || (request.getCountry() != null && !request.getCountry().isBlank())
                || (request.getPhoneNumber() != null && !request.getPhoneNumber().isBlank());
    }

    private void applyAddressUpdate(Address address, UpdateCarrierProfileRequest request) {
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
