package dev.faultlab.order;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "orders")
public class Order {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private int totalCents;
    private String status;
    private Instant createdAt;

    protected Order() {}
    public Order(int totalCents, String status) { this.totalCents = totalCents; this.status = status; this.createdAt = Instant.now(); }

    public Long getId() { return id; }
    public int getTotalCents() { return totalCents; }
    public String getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
}
