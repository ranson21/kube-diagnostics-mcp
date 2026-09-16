import { Component } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

@Component({
  selector: 'fl-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <header>
      <strong>Faultlab Shop</strong>
      <a routerLink="/" routerLinkActive="active" [routerLinkActiveOptions]="{ exact: true }">Home</a>
      <a routerLink="/products" routerLinkActive="active">Products</a>
      <a routerLink="/checkout" routerLinkActive="active">Checkout</a>
      <a routerLink="/admin" routerLinkActive="active">Admin</a>
    </header>
    <main><router-outlet /></main>
  `,
})
export class App {}
