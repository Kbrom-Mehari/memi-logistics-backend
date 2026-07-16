package com.memilogistics.shipmentservice.shipment.service;

import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.companyprofile.repository.CompanyProfileRepository;
import com.memilogistics.shipmentservice.shipment.dto.*;
import com.memilogistics.shipmentservice.shipment.entity.Shipment;
import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.shipment.mapper.ShipmentMapper;
import com.memilogistics.shipmentservice.shipment.repository.ShipmentRepository;
import com.memilogistics.shipmentservice.userprofile.entity.UserProfile;
import com.memilogistics.shipmentservice.userprofile.repository.UserProfileRepository;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.*;

import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;


class ShipmentServiceTest {


    private final ShipmentRepository shipmentRepository =
            mock(ShipmentRepository.class);

    private final UserProfileRepository userProfileRepository =
            mock(UserProfileRepository.class);

    private final CompanyProfileRepository companyProfileRepository =
            mock(CompanyProfileRepository.class);

    private final ShipmentMapper shipmentMapper =
            mock(ShipmentMapper.class);


    private final ShipmentService shipmentService =
            new ShipmentService(
                    shipmentRepository,
                    userProfileRepository,
                    companyProfileRepository,
                    shipmentMapper
            );


    private final CustomUserPrincipal user =
            new CustomUserPrincipal(
                    "721a3648-5249-43c2-ad62-cd73e89fb2bb",
                    List.of("ROLE_USER")
            );


    @Test
    void getShipment_shouldReturnShipment() {

        Shipment shipment = new Shipment();
        shipment.setId(1L);


        when(shipmentRepository.findById(1L))
                .thenReturn(Optional.of(shipment));


        Shipment result =
                shipmentService.getShipment(1L);


        assertEquals(shipment, result);

        verify(shipmentRepository)
                .findById(1L);
    }



    @Test
    void getShipment_shouldThrowWhenNotFound() {

        when(shipmentRepository.findById(1L))
                .thenReturn(Optional.empty());


        assertThrows(
                IllegalArgumentException.class,
                () -> shipmentService.getShipment(1L)
        );
    }



    @Test
    void getShipmentByTrackingNumber_shouldReturnResponse() {

        Shipment shipment = new Shipment();

        ShipmentResponse response =
                mock(ShipmentResponse.class);


        when(shipmentRepository.findByTrackingNumber("TRK123"))
                .thenReturn(Optional.of(shipment));


        when(shipmentMapper.toResponse(shipment))
                .thenReturn(response);



        ShipmentResponse result =
                shipmentService.getShipmentByTrackingNumber("TRK123");


        assertEquals(response, result);
    }



    @Test
    void getShipmentByTrackingNumber_shouldRejectBlankTrackingNumber() {


        assertThrows(
                IllegalArgumentException.class,
                () ->
                        shipmentService.getShipmentByTrackingNumber("")
        );
    }




    @Test
    void listShipments_shouldReturnMappedList() {


        Shipment shipment = new Shipment();


        Page<Shipment> page =
                new PageImpl<>(List.of(shipment));


        when(shipmentRepository.findAll(any(Pageable.class)))
                .thenReturn(page);


        List<ShipmentResponse> responses =
                List.of(mock(ShipmentResponse.class));


        when(shipmentMapper.toResponseList(List.of(shipment)))
                .thenReturn(responses);



        List<ShipmentResponse> result =
                shipmentService.listShipments(0,10);


        assertEquals(responses,result);
    }





    @Test
    void findCurrentUserShipments_shouldReturnPage() {


        Shipment shipment = new Shipment();


        Page<Shipment> shipments =
                new PageImpl<>(List.of(shipment));


        ShipmentResponse response =
                mock(ShipmentResponse.class);



        when(
                shipmentRepository
                        .findByShipperAuthenticationId(
                                eq(user.getId()),
                                any(Pageable.class)
                        )
        )
                .thenReturn(shipments);



        when(shipmentMapper.toResponse(shipment))
                .thenReturn(response);



        Page<ShipmentResponse> result =
                shipmentService.findCurrentUserShipments(
                        user,
                        0,
                        10
                );



        assertEquals(
                1,
                result.getContent().size()
        );
    }





    @Test
    void updateShipment_shouldUpdateOwnedShipment() {


        Shipment shipment = new Shipment();

        UserProfile profile = new UserProfile();
        profile.setAuthenticationId(user.getId());


        shipment.setShipper(profile);



        UpdateShipmentRequest update =
                new UpdateShipmentRequest();

        update.setDestination("Addis Ababa");


        when(shipmentRepository.findById(1L))
                .thenReturn(Optional.of(shipment));


        when(shipmentRepository.save(shipment))
                .thenReturn(shipment);



        Shipment result =
                shipmentService.updateShipment(
                        1L,
                        update,
                        user
                );



        assertEquals(
                "Addis Ababa",
                result.getDestination()
        );
    }





    @Test
    void updateShipment_shouldThrowWhenNotOwner() {


        Shipment shipment = new Shipment();


        UserProfile profile = new UserProfile();

        profile.setAuthenticationId(
                UUID.randomUUID().toString()
        );


        shipment.setShipper(profile);



        when(shipmentRepository.findById(1L))
                .thenReturn(Optional.of(shipment));



        UpdateShipmentRequest update =
                new UpdateShipmentRequest();



        assertThrows(
                ResponseStatusException.class,
                () ->
                        shipmentService.updateShipment(
                                1L,
                                update,
                                user
                        )
        );
    }





    @Test
    void deleteShipment_shouldDeleteOwnedPendingShipment() {


        Shipment shipment = new Shipment();


        UserProfile profile = new UserProfile();

        profile.setAuthenticationId(
                user.getId()
        );


        shipment.setShipper(profile);
        shipment.setStatus(ShipmentStatus.PENDING);



        when(shipmentRepository.findById(1L))
                .thenReturn(Optional.of(shipment));



        shipmentService.deleteShipment(
                1L,
                user
        );



        verify(shipmentRepository)
                .delete(shipment);
    }





    @Test
    void deleteShipment_shouldRejectUnauthorizedUser() {


        Shipment shipment = new Shipment();


        UserProfile profile = new UserProfile();

        profile.setAuthenticationId(
                "another-user"
        );


        shipment.setShipper(profile);
        shipment.setStatus(ShipmentStatus.PENDING);



        when(shipmentRepository.findById(1L))
                .thenReturn(Optional.of(shipment));



        assertThrows(
                ResponseStatusException.class,
                () ->
                        shipmentService.deleteShipment(
                                1L,
                                user
                        )
        );


        verify(shipmentRepository, never())
                .delete(any());
    }

}