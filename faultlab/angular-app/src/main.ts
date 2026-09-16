import { bootstrapApplication } from '@angular/platform-browser';
import { App } from './app/app';
import { appConfig } from './app/app.config';

// FAULT (frontend/bundle): the whole of lodash and moment (with every locale) are
// pulled into the main bundle and then barely used. Both are CommonJS, so the
// bundler cannot tree-shake them. Fix: drop them, or import single functions
// (e.g. `import chunk from 'lodash-es/chunk'`) and use `date-fns`/Intl instead of moment.
import * as _ from 'lodash';
import moment from 'moment';
import 'moment/min/locales';
(globalThis as any).__faultlab = { lodashVersion: _.VERSION, builtAt: moment().toISOString() };

// RUM client (kube-diagnostics-mcp): privacy-first beacons to the probe sidecar via /__rum.
import { initRum } from '@kube-diagnostics/rum-client';
export const rum = initRum({ app: 'faultlab', endpoint: '/__rum', sampleRate: 1 });

bootstrapApplication(App, appConfig).catch((err) => console.error(err));
