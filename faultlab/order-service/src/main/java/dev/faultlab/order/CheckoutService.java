package dev.faultlab.order;

import jakarta.persistence.EntityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CheckoutService {
    private static final Logger log = LoggerFactory.getLogger(CheckoutService.class);
    private final EntityManager em;
    private final OrderRepository orders;

    CheckoutService(EntityManager em, OrderRepository orders) { this.em = em; this.orders = orders; }

    /**
     * FAULT (performance/connection-pool-exhaustion): holds a pooled connection for 5 s inside the
     * transaction (a "payment gateway call" done with the connection checked out). With
     * spring.datasource.hikari.maximum-pool-size=2, the third concurrent checkout waits for
     * connection-timeout and then fails; hikaricp_connections_pending climbs and the DB health
     * indicator starts timing out. Fix: do slow external calls outside the transaction and size the
     * pool for the expected concurrency.
     */
    @Transactional
    public Order checkout(int totalCents) {
        log.info("checkout started, total={} cents (holding DB connection for 5 s)", totalCents);
        em.createNativeQuery("select pg_sleep(5)").getSingleResult();
        Order o = orders.save(new Order(totalCents, "CONFIRMED"));
        log.info("checkout finished, orderId={}", o.getId());
        return o;
    }
}
