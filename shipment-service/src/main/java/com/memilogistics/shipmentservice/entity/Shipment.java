package com.memilogistics.shipmentservice.entity;

import com.memilogistics.shipmentservice.enums.ShipmentStatus;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Setter
@Getter
@Table(name = "shipments")
public class Shipment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private LocalDate pickupDate;

    @Column
    private LocalDate estimatedDeliveryDate;

    private String shipmentItem;

    private String description;

    @Column
    private boolean fragile = false; //default value

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column
    private LocalDateTime updatedAt;

    private LocalDateTime completedAt;



    @Column(nullable = false, unique = true, length = 64)
    private String trackingNumber;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private ShipmentStatus status = ShipmentStatus.PENDING;

    @Column(nullable = false, length = 128)
    private String origin;

    @Column(nullable = false, length = 128)
    private String destination;

    @Column(precision = 10, scale = 2)
    private BigDecimal weightKg;

    @Column(precision = 10, scale = 2)
    private BigDecimal volume;

    @OneToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    private DeliveryConfirmation deliveryConfirmation;

    @OneToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    private PaymentRecord paymentRecord;

    @ManyToOne()
    @JoinColumn(name = "shipper_profile_id")
    private ShipperProfile shipper;

    @ManyToOne()
    @JoinColumn(name = "assigned_carrier_id")
    private CarrierCompany assignedCarrier;

    @OneToMany(
            mappedBy = "shipment",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    private List<ShipmentOffer> shipmentOffers = new ArrayList<>();

    @OneToMany(
            mappedBy = "shipment",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    private List<ShipmentEvent> shipmentEvents = new ArrayList<>();

    public void addShipmentEvent(ShipmentEvent event) {
        shipmentEvents.add(event);
        event.setShipment(this);
    }

    public void addPaymentRecord(PaymentRecord paymentRecord) {
        this.paymentRecord = paymentRecord;
        paymentRecord.setShipment(this);
    }
    public void addDeliveryConfirmation(
            DeliveryConfirmation confirmation
    ) {
        this.deliveryConfirmation = confirmation;

        if (confirmation != null) {
            confirmation.setShipment(this);
        }
    }

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

}
