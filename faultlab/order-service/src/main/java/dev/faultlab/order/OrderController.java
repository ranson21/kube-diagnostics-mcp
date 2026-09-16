package dev.faultlab.order;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

@RestController
public class OrderController {
    private static final Logger log = LoggerFactory.getLogger(OrderController.class);

    private final CheckoutService checkoutService;
    private final OrderRepository orders;

    OrderController(CheckoutService checkoutService, OrderRepository orders) {
        this.checkoutService = checkoutService;
        this.orders = orders;
    }

    public record CartItem(long productId, String name, int qty, int priceCents) {}
    public record Cart(List<CartItem> items, int totalCents) {}
    public record CheckoutResult(long orderId, String status, int totalCents) {}

    private static final Cart STATIC_CART = new Cart(List.of(
            new CartItem(1, "Rugged Lantern #1", 1, 2499),
            new CartItem(7, "Heavy-duty Water Filter #7", 2, 8900),
            new CartItem(12, "Copper Kettle #12", 1, 5450)), 2499 + 2 * 8900 + 5450);

    @GetMapping("/cart")
    public Cart cart() { return STATIC_CART; }

    @PostMapping("/checkout")
    public CheckoutResult checkout(@RequestBody(required = false) Cart cart) {
        int total = cart == null ? STATIC_CART.totalCents() : cart.totalCents();
        Order o = checkoutService.checkout(total);
        return new CheckoutResult(o.getId(), o.getStatus(), o.getTotalCents());
    }

    @GetMapping("/orders")
    public List<Order> list() { return orders.findAll(); }

    // ---------------------------------------------------------------------------------------
    // FAULT (pod/memory-leak): every /admin/report call allocates 512 KiB and parks it in a static
    // list that is never cleared. The container is limited to 256Mi and the heap is allowed to
    // use ~90% of it (see k8s manifest), so after roughly 60-100 calls (1-2 min of load-test) the pod is OOMKilled (exit 137) and
    // restarts. Fix: don't retain the report buffers (or use a bounded cache).
    // ---------------------------------------------------------------------------------------
    private static final List<byte[]> RETAINED_REPORTS = new ArrayList<>();
    private static final AtomicInteger REPORT_SEQ = new AtomicInteger();
    private static final int REPORT_BYTES = 512 * 1024;

    public record AdminReport(int reportId, long retainedMiB, int entries, Instant generatedAt) {}

    @GetMapping("/admin/report")
    public AdminReport adminReport() {
        byte[] buf = new byte[REPORT_BYTES];
        ThreadLocalRandom.current().nextBytes(buf);
        long retained;
        synchronized (RETAINED_REPORTS) {
            RETAINED_REPORTS.add(buf);
            retained = (long) RETAINED_REPORTS.size() * REPORT_BYTES / (1024 * 1024);
        }
        int id = REPORT_SEQ.incrementAndGet();
        log.info("admin report {} generated, retained={} MiB", id, retained);
        return new AdminReport(id, retained, RETAINED_REPORTS.size(), Instant.now());
    }

    // ---------------------------------------------------------------------------------------
    // FAULT (performance/thread-deadlock): creates two threads that lock two monitors in opposite
    // order. They stay BLOCKED forever (visible in /actuator/threaddump as "deadlock-worker-a/b",
    // and jstack reports "Found 1 deadlock"). The request itself returns immediately.
    // Fix: always acquire locks in a consistent global order (or use a single lock / tryLock).
    // ---------------------------------------------------------------------------------------
    private static final Object LOCK_A = new Object();
    private static final Object LOCK_B = new Object();
    private static final AtomicInteger DEADLOCKS = new AtomicInteger();

    @GetMapping("/orders/deadlock")
    public Map<String, Object> deadlock() {
        int n = DEADLOCKS.incrementAndGet();
        Thread a = new Thread(() -> lockInOrder(LOCK_A, LOCK_B), "deadlock-worker-a-" + n);
        Thread b = new Thread(() -> lockInOrder(LOCK_B, LOCK_A), "deadlock-worker-b-" + n);
        a.setDaemon(true); b.setDaemon(true);
        a.start(); b.start();
        log.warn("deadlock created between {} and {}", a.getName(), b.getName());
        return Map.of("status", "deadlock created", "threads", List.of(a.getName(), b.getName()), "count", n);
    }

    private static void lockInOrder(Object first, Object second) {
        synchronized (first) {
            try { Thread.sleep(200); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
            synchronized (second) {
                log.info("unexpectedly acquired both locks");
            }
        }
    }
}
