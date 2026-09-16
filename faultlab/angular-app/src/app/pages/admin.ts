import { Component, OnInit, inject, signal } from '@angular/core';
import { Api, AdminReport } from '../api';

@Component({
  selector: 'fl-admin',
  template: `
    <h1>Admin report</h1>
    @if (report(); as r) {
      <div class="card">
        <div>Report #{{ r.reportId }} generated {{ r.generatedAt }}</div>
        <div>Entries: {{ r.entries }} — retained: {{ r.retainedMiB }} MiB</div>
      </div>
    } @else if (error()) { <p class="error">{{ error() }}</p> } @else { <p>Generating…</p> }
  `,
})
export class Admin implements OnInit {
  private api = inject(Api);
  report = signal<AdminReport | null>(null);
  error = signal<string | null>(null);

  ngOnInit(): void {
    this.api.adminReport().subscribe({
      next: (r) => this.report.set(r),
      error: (e) => this.error.set(`Failed to load report: ${e.status ?? e.message}`),
    });

    // FAULT (frontend/JS errors): ~30% of visits throw an uncaught error from a timer callback.
    // It escapes Angular's ErrorHandler and surfaces via window.onerror / the 'error' event,
    // which is exactly what a RUM client reports. Fix: guard the widget and handle its errors.
    if (Math.random() < 0.3) {
      setTimeout(() => {
        const widget: any = undefined;
        widget.render(); // TypeError: Cannot read properties of undefined (reading 'render')
      }, 50);
    }
  }
}
