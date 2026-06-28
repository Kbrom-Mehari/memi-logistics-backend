package com.memilogistics.shipmentservice.service;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.CarrierCompanyResponse;
import com.memilogistics.shipmentservice.dto.CreateCarrierProfileRequest;
import com.memilogistics.shipmentservice.dto.ShipmentResponse;
import com.memilogistics.shipmentservice.dto.UpdateCarrierProfileRequest;
import com.memilogistics.shipmentservice.address.entity.Address;
import com.memilogistics.shipmentservice.entity.CarrierCompany;
import com.memilogistics.shipmentservice.mapper.ProfileMapper;
import com.memilogistics.shipmentservice.mapper.ShipmentMapper;
import com.memilogistics.shipmentservice.repository.AddressRepository;
import com.memilogistics.shipmentservice.repository.CarrierCompanyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CarrierProfileService {
    private final CarrierCompanyRepository carrierCompanyRepository;
    private final AddressRepository addressRepository;
    private final ProfileMapper profileMapper;
    private final ShipmentMapper shipmentMapper;

    @Transactional
    public CarrierCompanyResponse createCarrierCompanyProfile(@CurrentUser CustomUserPrincipal user,
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

        var carrierCompany = carrierCompanyRepository.save(company);
        return profileMapper.toCarrierCompanyResponse(carrierCompany);
    }

    @Transactional
    public CarrierCompanyResponse updateCarrierCompanyProfile(@CurrentUser CustomUserPrincipal user,
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

        var carrierCompany = carrierCompanyRepository.save(company);
        return profileMapper.toCarrierCompanyResponse(carrierCompany);
    }

    public CarrierCompanyResponse getCarrierProfile(@CurrentUser CustomUserPrincipal user){
        var profile = carrierCompanyRepository.findByAuthenticationEmail(user.getUsername()).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Carrier profile not found")
        );

        return profileMapper.toCarrierCompanyResponse(profile);
    }

    public CarrierCompanyResponse getCarrierCompany(Long carrierCompanyId) {
        var company = carrierCompanyRepository.findById(carrierCompanyId).orElseThrow(
                ()-> new ResponseStatusException(HttpStatus.NOT_FOUND, "Carrier company not found with id: " + carrierCompanyId)
        );
        return profileMapper.toCarrierCompanyResponse(company);
    }

    public List<ShipmentResponse> getAssignedShipments(
            @CurrentUser CustomUserPrincipal user
    ) {
        var carrier = carrierCompanyRepository.findByAuthenticationEmail(user.getUsername()).orElseThrow(
                ()-> new ResponseStatusException(HttpStatus.NOT_FOUND, "Carrier company not found")
        );
        var shipments = carrier.getAssignedShipments();
        return shipmentMapper.toResponseList(shipments);
    }

    public List<ShipmentResponse> getAssignedShipments(Long carrierId){
        var carrier = carrierCompanyRepository.findById(carrierId).orElseThrow(
                ()-> new ResponseStatusException(HttpStatus.NOT_FOUND, "Carrier company not found")
        );
        var shipments = carrier.getAssignedShipments();
        return shipmentMapper.toResponseList(shipments);
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
