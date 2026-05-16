package com.memilogistics.shipmentservice.exception;

import com.memilogistics.shipmentservice.enums.ShipmentStatus;

public class InvalidShipmentStatusTransitionException extends RuntimeException {
    public InvalidShipmentStatusTransitionException(ShipmentStatus current,
                                                    ShipmentStatus next) {
        super("Invalid shipment status transition from " + current + " to " + next);
    }
}
