package com.memilogistics.shipmentservice.enums;

public enum ShipmentStatus {
    PENDING,
    ACCEPTED,
    ASSIGNED,
    PICKED_UP,
    IN_TRANSIT,
    ARRIVED_AT_DESTINATION,
    DELIVERED,
    COMPLETED;

    public boolean canTransitionTo(ShipmentStatus nextStatus) {
        if (nextStatus == null) return false;
        if (this == nextStatus) return true; // Allow no-op transitions

        return switch (this) {
            case PENDING -> nextStatus == ACCEPTED;
            case ACCEPTED -> nextStatus == ASSIGNED;
            case ASSIGNED -> nextStatus == PICKED_UP;
            case PICKED_UP -> nextStatus == IN_TRANSIT;
            case IN_TRANSIT -> nextStatus == ARRIVED_AT_DESTINATION;
            case ARRIVED_AT_DESTINATION -> nextStatus == DELIVERED;
            case DELIVERED -> nextStatus == COMPLETED;
            case COMPLETED -> false;
        };
    }
}
