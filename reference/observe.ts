import type { IncomingMessage, ServerResponse } from 'node:http';
import { newRequestId, traceIdOf } from './log.ts';
import type { Logger } from './log.ts';
import type { Metrics } from './metrics.ts';

export type Observability = { metrics?: Metrics; logger?: Logger };
/**
 * Adds `x-request-id` to the response and records one metric sample and one log line per
 * request when it completes. `route` must be a fixed route template, never a raw URL.
 */
export function observe(listener: string, req: IncomingMessage, res: ServerResponse, obs: Observability) {
  const requestId = newRequestId(), traceId = traceIdOf(String(req.headers.traceparent ?? ""));
  const start = performance.now();
  let route = 'unmatched', done = false;
  res.setHeader('x-request-id', requestId);
  res.once('close', () => {
    if (done) return; done = true;
    const seconds = (performance.now() - start) / 1000, status = res.headersSent ? res.statusCode : 499;
    obs.metrics?.request(listener, route, status, seconds);
    obs.logger?.info('request', { listener, method: req.method, route, status, durationMs: Math.round(seconds * 1000), requestId, traceId });
  });
  return { requestId, traceId, setRoute(label: string) { route = label; } };
}
