package com.memilogistics.shipmentservice.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class DashboardInformation {
    private Long pendingShipments;
    private Long completedShipments;
    private Long fragileShipments;
    private Long nonFragileShipments;
    private Long numberOfShippers;
    private Long numberOfCarriers;
    private Long totalUsers;
    private Long totalShipments;
}
