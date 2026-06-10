package com.memilogistics.shipmentservice.controller;

import com.memilogistics.shipmentservice.dto.DashboardInformation;
import com.memilogistics.shipmentservice.service.ShipmentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
public class DashBoardController {
    private final ShipmentService shipmentService;

    @GetMapping("/information")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<DashboardInformation>  getDashboardInformation() {
        return ResponseEntity.ok(shipmentService.getDashboardInformation());
    }
}
