package com.memilogistics.shipmentservice.dto;

import com.memilogistics.shipmentservice.enums.PaymentMethod;
import lombok.Getter;
import lombok.Setter;

import java.math.BigDecimal;
import java.util.Currency;

@Getter
@Setter
public class PaymentRequest {
    private String currencyCode;
    private BigDecimal amount;
    private PaymentMethod paymentMethod;
    private String note;
}
