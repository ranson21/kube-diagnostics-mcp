import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', loadComponent: () => import('./pages/home').then(m => m.Home), title: 'Faultlab Shop' },
  { path: 'products', loadComponent: () => import('./pages/products').then(m => m.Products), title: 'Products' },
  { path: 'products/:id', loadComponent: () => import('./pages/product-detail').then(m => m.ProductDetail), title: 'Product' },
  { path: 'checkout', loadComponent: () => import('./pages/checkout').then(m => m.Checkout), title: 'Checkout' },
  { path: 'admin', loadComponent: () => import('./pages/admin').then(m => m.Admin), title: 'Admin' },
  { path: '**', redirectTo: '' },
];
