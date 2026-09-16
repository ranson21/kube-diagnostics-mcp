package dev.faultlab.catalog;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "reviews")
public class Review {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private Long productId;
    private Long authorId;   // plain FK column, deliberately not a @ManyToOne -> see ReviewController
    private int rating;
    private String body;

    public Long getId() { return id; }
    public Long getProductId() { return productId; }
    public Long getAuthorId() { return authorId; }
    public int getRating() { return rating; }
    public String getBody() { return body; }
}
