package com.memilogistics.shipmentservice.controller;

import com.memilogistics.commonsecurity.annotation.CurrentUser;
import com.memilogistics.commonsecurity.principal.CustomUserPrincipal;
import com.memilogistics.shipmentservice.dto.PaymentRequest;
import com.memilogistics.shipmentservice.service.PaymentRecordService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/shipments")
@RequiredArgsConstructor
public class PaymentAndCompletionController {
    private final PaymentRecordService paymentRecordService;

    @PostMapping("/{shipmentId}/initiate-payment")
    public ResponseEntity<Void> initiatePayment(
            @PathVariable Long shipmentId,
            @RequestBody PaymentRequest request
    ){
        paymentRecordService.initiatePayment(shipmentId, request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{shipmentId}/confirm-payment")
    public ResponseEntity<Void> confirmPayment(
            @PathVariable Long shipmentId,
            @CurrentUser CustomUserPrincipal principal
    ){
        paymentRecordService.confirmPayment(shipmentId, principal);
        return ResponseEntity.ok().build();
    }
}
