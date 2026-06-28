package com.memilogistics.shipmentservice.dto;

import lombok.Data;

@Data
public class CancelShipmentOfferRequest {
    private Long carrierId;
    private Long ShipmentOfferId;
}
