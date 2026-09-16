import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'fl-home',
  imports: [RouterLink],
  template: `
    <div class="card">
      <h1>Welcome to Faultlab Shop</h1>
      <p>A deliberately broken demo storefront used to integration-test kube-diagnostics-mcp.</p>
      <p><a routerLink="/products">Browse products</a></p>
    </div>
  `,
})
export class Home {}
