import { ApplicationConfig, provideZonelessChangeDetection, inject, provideAppInitializer } from '@angular/core';
import { provideRouter, Router, NavigationStart, NavigationEnd } from '@angular/router';
import { rum } from '../main';
import { provideHttpClient, withFetch } from '@angular/common/http';
import { routes } from './app.routes';

export const appConfig: ApplicationConfig = {
  providers: [
    provideZonelessChangeDetection(),
    provideRouter(routes),
    provideHttpClient(withFetch()),
    // Report SPA route changes to RUM as route PATTERNS (e.g. /products/:id), never concrete URLs.
    provideAppInitializer(() => {
      const router = inject(Router);
      let started = performance.now();
      router.events.subscribe((e) => {
        if (e instanceof NavigationStart) started = performance.now();
        if (e instanceof NavigationEnd) {
          let node = router.routerState.snapshot.root;
          const parts: string[] = [];
          while (node) {
            if (node.routeConfig?.path) parts.push(node.routeConfig.path);
            node = node.firstChild!;
          }
          rum.routeChanged('/' + parts.join('/'), performance.now() - started);
        }
      });
    }),
  ],
};
