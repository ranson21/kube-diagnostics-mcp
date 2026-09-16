import { Component, OnInit, inject, signal } from '@angular/core';
import { Api, Cart, CheckoutResult } from '../api';

@Component({
  selector: 'fl-checkout',
  template: `
    <h1>Checkout</h1>
    @if (cart(); as c) {
      <div class="card">
        @for (item of c.items; track item.productId) {
          <div>{{ item.qty }} × {{ item.name }} — {{ (item.priceCents / 100).toFixed(2) }} USD</div>
        }
        <p><strong>Total: {{ (c.totalCents / 100).toFixed(2) }} USD</strong></p>
        <button (click)="placeOrder()" [disabled]="busy()">Place order</button>
      </div>
    } @else { <p>Loading cart…</p> }
    @if (result(); as r) { <p class="card">Order {{ r.orderId }}: {{ r.status }}</p> }
    @if (error()) { <p class="error">{{ error() }}</p> }
  `,
})
export class Checkout implements OnInit {
  private api = inject(Api);
  cart = signal<Cart | null>(null);
  result = signal<CheckoutResult | null>(null);
  error = signal<string | null>(null);
  busy = signal(false);

  ngOnInit(): void {
    // FAULT (frontend/INP+TBT): synchronous 800 ms busy loop on the main thread while the
    // route renders ("price validation"). Fix: remove it, or move the work to a Web Worker /
    // make it async and chunked.
    const until = performance.now() + 800;
    let x = 0;
    while (performance.now() < until) { x = (x + Math.sqrt(x + 1)) % 1e6; }
    (globalThis as any).__faultlab_checkout_spin = x;

    this.api.cart().subscribe({
      next: (c) => this.cart.set(c),
      error: (e) => this.error.set(`Failed to load cart: ${e.status ?? e.message}`),
    });
  }

  placeOrder(): void {
    const c = this.cart();
    if (!c) return;
    this.busy.set(true);
    this.error.set(null);
    this.api.checkout(c).subscribe({
      next: (r) => { this.result.set(r); this.busy.set(false); },
      error: (e) => { this.error.set(`Checkout failed: HTTP ${e.status ?? '?'} ${e.statusText ?? e.message}`); this.busy.set(false); },
    });
  }
}
