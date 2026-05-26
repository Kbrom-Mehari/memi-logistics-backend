package com.memilogistics.shipmentservice.controller;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.PaymentRequest;
import com.memilogistics.shipmentservice.service.PaymentRecordService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/payment")
@RequiredArgsConstructor
public class PaymentAndCompletionController {
    private final PaymentRecordService paymentRecordService;

    @PostMapping("/{shipmentId}/initiate-payment")
    @PreAuthorize("hasRole('SHIPPER')")
    public ResponseEntity<Void> initiatePayment(
            @PathVariable("shipmentId") Long shipmentId,
            @RequestBody PaymentRequest request
    ){
        paymentRecordService.initiatePayment(shipmentId, request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{shipmentId}/confirm-payment")
    @PreAuthorize("hasRole('CARRIER')")
    public ResponseEntity<Void> confirmPayment(
            @PathVariable("shipmentId") Long shipmentId,
            @CurrentUser CustomUserPrincipal principal
    ){
        paymentRecordService.confirmPayment(shipmentId, principal);
        return ResponseEntity.ok().build();
    }
}
