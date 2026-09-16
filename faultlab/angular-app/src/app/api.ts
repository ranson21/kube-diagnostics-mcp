import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Product { id: number; name: string; description: string; priceCents: number; }
export interface Review { id: number; productId: number; rating: number; body: string; authorName: string; authorEmail: string; }
export interface Cart { items: { productId: number; name: string; qty: number; priceCents: number }[]; totalCents: number; }
export interface CheckoutResult { orderId: number; status: string; totalCents: number; }
export interface AdminReport { reportId: number; retainedMiB: number; entries: number; generatedAt: string; }

/**
 * All paths go through the nginx proxy. Routing table (see faultlab/README.md):
 *   /api/catalog/*   -> catalog-service:8080/*
 *   /api/orders/*    -> order-service:8080/orders/*
 *   /api/cart        -> order-service:8080/cart
 *   /api/checkout    -> order-service:8080/checkout
 *   /api/admin/*     -> order-service:8080/admin/*
 */
@Injectable({ providedIn: 'root' })
export class Api {
  private http = inject(HttpClient);

  products(): Observable<Product[]> { return this.http.get<Product[]>('/api/catalog/products'); }
  product(id: string): Observable<Product> { return this.http.get<Product>(`/api/catalog/products/${id}`); }
  reviews(productId: string): Observable<Review[]> {
    return this.http.get<Review[]>('/api/catalog/reviews', { params: { productId } });
  }
  slowProduct(): Observable<Product> { return this.http.get<Product>('/api/catalog/products/slow'); }
  cart(): Observable<Cart> { return this.http.get<Cart>('/api/cart'); }
  checkout(cart: Cart): Observable<CheckoutResult> { return this.http.post<CheckoutResult>('/api/checkout', cart); }
  adminReport(): Observable<AdminReport> { return this.http.get<AdminReport>('/api/admin/report'); }
}
