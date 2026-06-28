package com.memilogistics.shipmentservice.payment.dto;

import com.memilogistics.shipmentservice.payment.enums.PaymentMethod;
import lombok.Getter;
import lombok.Setter;

import java.math.BigDecimal;

@Getter
@Setter
public class PaymentRequest {
    private String currencyCode;
    private BigDecimal amount;
    private PaymentMethod paymentMethod;
    private String note;
}
