package dev.faultlab.catalog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.List;

@RestController
public class CatalogController {
    private static final Logger log = LoggerFactory.getLogger(CatalogController.class);

    private final ProductRepository products;
    private final ReviewRepository reviews;
    private final AuthorRepository authors;

    CatalogController(ProductRepository products, ReviewRepository reviews, AuthorRepository authors) {
        this.products = products;
        this.reviews = reviews;
        this.authors = authors;
    }

    @GetMapping("/products")
    public List<Product> list() {
        return products.findAll();
    }

    /** FAULT (performance/slow-endpoint): sleeps 3 s, longer than the proxy's 2 s read timeout -> 504. */
    @GetMapping("/products/slow")
    public Product slow() throws InterruptedException {
        log.info("slow product lookup: simulating a 3000 ms upstream dependency");
        Thread.sleep(3000);
        return products.findById(1L).orElseThrow();
    }

    @GetMapping("/products/{id}")
    public Product get(@PathVariable Long id) {
        // FAULT (security/PII-in-logs): logs a customer email and a card-looking number at INFO on
        // every request. Values are fake (RFC 2606 domain, Visa test PAN). Fix: never log PII;
        // log only the product id and an opaque customer reference.
        log.info("product {} viewed by customer jane.doe@example.com (card on file 4111 1111 1111 1111)", id);
        return products.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "no such product"));
    }

    public record ReviewView(Long id, Long productId, int rating, String body, String authorName, String authorEmail) {}

    /**
     * FAULT (performance/N+1): loads the reviews for a product (1 query) and then the author for
     * each review individually (N queries). With ~10 reviews per product that is 11 round-trips;
     * pg_stat_statements shows "select ... from authors where id=$1" with a huge call count.
     * Fix: a single JOIN (e.g. @Query("select r, a from Review r join Author a on a.id = r.authorId
     * where r.productId = :productId")) or fetch all authors with findAllById(authorIds).
     */
    @GetMapping("/reviews")
    public List<ReviewView> reviews(@RequestParam Long productId) {
        List<ReviewView> out = new ArrayList<>();
        for (Review r : reviews.findByProductIdOrderByIdAsc(productId)) {
            Author a = authors.findById(r.getAuthorId()).orElse(null);       // <- one query per review
            out.add(new ReviewView(r.getId(), r.getProductId(), r.getRating(), r.getBody(),
                    a == null ? "unknown" : a.getName(), a == null ? "" : a.getEmail()));
        }
        return out;
    }
}
