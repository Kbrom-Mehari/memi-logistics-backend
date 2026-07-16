package com.memilogistics.shipmentservice.dashboard;

import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.shipment.repository.ShipmentRepository;
import com.memilogistics.shipmentservice.userprofile.repository.UserProfileRepository;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class DashboardInformationServiceTest {

    private final ShipmentRepository shipmentRepository =
            mock(ShipmentRepository.class);

    private final UserProfileRepository userProfileRepository =
            mock(UserProfileRepository.class);


    private final DashboardInformationService dashboardInformationService =
            new DashboardInformationService(
                    shipmentRepository,
                    userProfileRepository
            );


    @Test
    void getDashboardInformation_shouldReturnCorrectStatistics() {

        // Arrange
        when(shipmentRepository.countByStatus(ShipmentStatus.PENDING))
                .thenReturn(15L);

        when(shipmentRepository.countByStatus(ShipmentStatus.COMPLETED))
                .thenReturn(30L);

        when(shipmentRepository.countByFragile(true))
                .thenReturn(8L);

        when(shipmentRepository.countByFragile(false))
                .thenReturn(42L);

        when(userProfileRepository.count())
                .thenReturn(100L);

        when(shipmentRepository.count())
                .thenReturn(50L);


        // Act
        DashboardInformation result =
                dashboardInformationService.getDashboardInformation();


        // Assert
        assertEquals(
                15L,
                result.getPendingShipments()
        );

        assertEquals(
                30L,
                result.getCompletedShipments()
        );

        assertEquals(
                8L,
                result.getFragileShipments()
        );

        assertEquals(
                42L,
                result.getNonFragileShipments()
        );

        assertEquals(
                100L,
                result.getTotalUsers()
        );

        assertEquals(
                50L,
                result.getTotalShipments()
        );


        // Verify repository interactions
        verify(shipmentRepository)
                .countByStatus(ShipmentStatus.PENDING);

        verify(shipmentRepository)
                .countByStatus(ShipmentStatus.COMPLETED);

        verify(shipmentRepository)
                .countByFragile(true);

        verify(shipmentRepository)
                .countByFragile(false);

        verify(userProfileRepository)
                .count();

        verify(shipmentRepository)
                .count();
    }
}