package com.memilogistics.shipmentservice.dashboard;

import com.memilogistics.shipmentservice.shipment.enums.ShipmentStatus;
import com.memilogistics.shipmentservice.shipment.repository.ShipmentRepository;
import com.memilogistics.shipmentservice.userprofile.repository.UserProfileRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DashboardInformationService {
    private final ShipmentRepository shipmentRepository;
    private final UserProfileRepository userProfileRepository;

    public DashboardInformation getDashboardInformation() {
        return new DashboardInformation(
                shipmentRepository.countByStatus(ShipmentStatus.PENDING),
                shipmentRepository.countByStatus(ShipmentStatus.COMPLETED),
                shipmentRepository.countByFragile(true),
                shipmentRepository.countByFragile(false),
                userProfileRepository.count(),
                shipmentRepository.count()
        );
    }
}
