package com.memilogistics.shipmentservice.service;

import com.memilogistics.shipmentservice.entity.Shipment;
import com.memilogistics.shipmentservice.entity.ShipmentEvent;
import com.memilogistics.shipmentservice.repository.ShipmentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class ShipmentEventsServiceTest {

    @Mock
    private ShipmentRepository shipmentRepository;

    @InjectMocks
    private ShipmentEventsService shipmentEventsService;

    private Shipment sampleShipment;
    private List<ShipmentEvent> sampleEvents;

    @BeforeEach
    void setUp() {
        sampleShipment = new Shipment();
        sampleShipment.setId(1L);

        sampleEvents = new ArrayList<>();
        ShipmentEvent event1 = new ShipmentEvent();
        event1.setId(10L);
        event1.setDescription("Event 1");
        sampleEvents.add(event1);

        sampleShipment.setShipmentEvents(sampleEvents);
    }

    @Test
    void getShipmentEvents_ShouldReturnEvents_WhenShipmentExists() {
        when(shipmentRepository.findById(1L)).thenReturn(Optional.of(sampleShipment));

        List<ShipmentEvent> result = shipmentEventsService.getShipmentEvents(1L);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("Event 1", result.get(0).getDescription());

        verify(shipmentRepository).findById(1L);
    }

    @Test
    void getShipmentEvents_ShouldThrowException_WhenShipmentDoesNotExist() {
        when(shipmentRepository.findById(99L)).thenReturn(Optional.empty());

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> shipmentEventsService.getShipmentEvents(99L));

        assertEquals("Shipment not found with id: 99", exception.getMessage());
        verify(shipmentRepository).findById(99L);
    }
}

