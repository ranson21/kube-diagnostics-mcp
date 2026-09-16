import { Component, inject, signal } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { Api, Product, Review } from '../api';

@Component({
  selector: 'fl-product-detail',
  template: `
    <!-- FAULT (frontend/LCP+CLS): ~3 MB hero image, no width/height attributes,
         not lazy, not responsive. Fix: <img src="/assets/hero-large.webp" width="1400" height="900"
         fetchpriority="high" decoding="async"> with a properly compressed asset. -->
    <img src="/assets/hero-large.png" alt="Hero" style="max-width:100%">
    @if (product(); as p) {
      <div class="card">
        <h1>{{ p.name }}</h1>
        <p>{{ p.description }}</p>
        <p><strong>{{ (p.priceCents / 100).toFixed(2) }} USD</strong></p>
      </div>
    } @else if (error()) { <p class="error">{{ error() }}</p> } @else { <p>Loading…</p> }
    <h2>Reviews ({{ reviews().length }})</h2>
    @for (r of reviews(); track r.id) {
      <div class="card">
        <strong>{{ r.authorName }}</strong> rated {{ r.rating }}/5
        <p>{{ r.body }}</p>
      </div>
    }
  `,
})
export class ProductDetail {
  private api = inject(Api);
  private route = inject(ActivatedRoute);
  product = signal<Product | null>(null);
  reviews = signal<Review[]>([]);
  error = signal<string | null>(null);

  constructor() {
    this.route.paramMap.subscribe((params) => {
      const id = params.get('id')!;
      this.product.set(null);
      this.api.product(id).subscribe({
        next: (p) => this.product.set(p),
        error: (e) => this.error.set(`Failed to load product: ${e.status ?? e.message}`),
      });
      this.api.reviews(id).subscribe({ next: (r) => this.reviews.set(r), error: () => this.reviews.set([]) });
    });
  }
}
