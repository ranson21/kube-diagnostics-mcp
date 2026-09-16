# @kube-diagnostics/rum-client

Privacy-first real-user monitoring beacon for the `kube-diagnostics-mcp` probe. ~3 KB plus `web-vitals`.

## Angular

```ts
// main.ts
import { initRum } from "@kube-diagnostics/rum-client";
const rum = initRum({ app: "storefront", sampleRate: 1 });

// app.config.ts / AppComponent: report SPA route changes as PATTERNS
import { Router, NavigationEnd, NavigationStart } from "@angular/router";
let started = 0;
inject(Router).events.subscribe((e) => {
  if (e instanceof NavigationStart) started = performance.now();
  if (e instanceof NavigationEnd) {
    const pattern = router.routerState.snapshot.root.firstChild?.routeConfig?.path; // e.g. "products/:id"
    rum.routeChanged(pattern ? `/${pattern}` : e.urlAfterRedirects, performance.now() - started);
  }
});
```

## nginx

```nginx
location = /__rum {
  proxy_pass http://127.0.0.1:9911/rum;   # the probe sidecar in the same pod
  client_max_body_size 16k;
  access_log off;
}
```

The probe must run with `DIAG_PROBE_RUM_ENABLED=true`. Summaries are then available through the hub's `get_web_vitals`, `get_page_views`, `get_page_load_breakdown`, `get_browser_api_latency`, `get_frontend_errors`, and `diagnose_slow_page` tools, and as Prometheus metrics on the probe's `/metrics`.

## What is sent

Route patterns, vitals values, navigation phases, same-origin API paths with durations and status codes, error messages and stack signatures, a per-tab session id, coarse device class, effective connection type. Never: query strings, fragments, cookies, user ids, form values, IPs.
