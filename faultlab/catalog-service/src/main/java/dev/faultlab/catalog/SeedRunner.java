package dev.faultlab.catalog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/** Seeds 50 products, 25 authors and 500 reviews on first start (idempotent). */
@Component
public class SeedRunner implements CommandLineRunner {
    private static final Logger log = LoggerFactory.getLogger(SeedRunner.class);
    private static final String[] ADJ = {"Rugged", "Compact", "Solar", "Copper", "Cedar", "Folding", "Heavy-duty", "Cast-iron", "Insulated", "Hand-forged"};
    private static final String[] NOUN = {"Lantern", "Kettle", "Axe", "Trowel", "Water Filter", "Rain Barrel", "Seed Tray", "Canning Jar Set", "Fence Post Driver", "Wool Blanket"};
    private static final String[] BODIES = {"Does exactly what it says.", "Solid build, a little heavy.", "Arrived late but works great.",
            "Would buy again.", "Not worth the price.", "Perfect for the homestead.", "Broke after two weeks.", "Great value."};

    private final JdbcTemplate jdbc;

    SeedRunner(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @Override
    public void run(String... args) {
        Integer count = jdbc.queryForObject("select count(*) from products", Integer.class);
        if (count != null && count > 0) {
            log.info("catalog already seeded ({} products)", count);
            return;
        }
        Random rnd = new Random(42);
        List<Object[]> products = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            String name = ADJ[i % ADJ.length] + " " + NOUN[(i / ADJ.length + i) % NOUN.length] + " #" + (i + 1);
            products.add(new Object[]{name, "A dependable " + name.toLowerCase() + " for everyday use.", 500 + rnd.nextInt(20000)});
        }
        jdbc.batchUpdate("insert into products(name, description, price_cents) values (?, ?, ?)", products);

        List<Object[]> authors = new ArrayList<>();
        for (int i = 1; i <= 25; i++) {
            authors.add(new Object[]{"Reviewer " + i, "reviewer" + i + "@example.com"});
        }
        jdbc.batchUpdate("insert into authors(name, email) values (?, ?)", authors);

        List<Object[]> reviews = new ArrayList<>();
        for (int i = 0; i < 500; i++) {
            reviews.add(new Object[]{(long) (i % 50) + 1, (long) rnd.nextInt(25) + 1, 1 + rnd.nextInt(5), BODIES[rnd.nextInt(BODIES.length)]});
        }
        jdbc.batchUpdate("insert into reviews(product_id, author_id, rating, body) values (?, ?, ?, ?)", reviews);
        log.info("seeded {} products, {} authors, {} reviews", products.size(), authors.size(), reviews.size());
    }
}
