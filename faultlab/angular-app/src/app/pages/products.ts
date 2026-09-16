import { Component, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, Product } from '../api';

@Component({
  selector: 'fl-products',
  imports: [RouterLink],
  template: `
    <h1>Products</h1>
    @if (error()) { <p class="error">{{ error() }}</p> }
    @for (p of products(); track p.id) {
      <div class="card">
        <a [routerLink]="['/products', p.id]"><strong>{{ p.name }}</strong></a>
        <span> — {{ (p.priceCents / 100).toFixed(2) }} USD</span>
      </div>
    } @empty { <p>Loading…</p> }
  `,
})
export class Products {
  private api = inject(Api);
  products = signal<Product[]>([]);
  error = signal<string | null>(null);

  constructor() {
    this.api.products().subscribe({
      next: (list) => this.products.set(list),
      error: (e) => this.error.set(`Failed to load products: ${e.status ?? e.message}`),
    });
  }
}
