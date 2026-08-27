/**
 * HTTP/WS bridge factory — drop-in replacement for bridge.buildProvider / bridge.buildEmitter
 * that routes calls to aioncore via REST API and WebSocket.
 *
 * Exported helpers produce objects with the same shape as the local IPC bridge,
 * so existing renderer code works without changes.
 */

import { refreshSession, WS_CLOSE_POLICY_VIOLATION } from './sessionRefresh';

// ---------------------------------------------------------------------------
// Base URL
// ---------------------------------------------------------------------------

declare global {
  interface Window {
    __backendPort?: number;
  }
}

/**
 * Resolve the backend port, honoring both renderer and main-process contexts.
 *
 * - Renderer (Electron): the preload bridge writes `window.__backendPort` before
 *   the first HTTP call, so reading from window is authoritative.
 * - Renderer (WebUI browser): no preload, so `window.__backendPort` is missing.
 *   Requests must go to the same origin that served the page; web-host's
 *   static-server reverse-proxies `/api/*` and upgrades `/ws` to the backend
 *   port. See getBaseUrl / getWsUrl below for the WebUI branch.
 * - Main process: `window` is undefined. `src/index.ts` writes the port to
 *   `globalThis.__backendPort` immediately after `backendManager.start()`
 *   resolves, so any main-process ipcBridge caller (e.g. the one-shot
 *   assistant migration hook) hits the correct port.
 * - Fallback `13400` only applies when neither is initialized — the request
 *   will still fail cleanly with ECONNREFUSED rather than masking the bug.
 */
function getBackendPort(): number {
  if (typeof window !== 'undefined' && (window as Window).__backendPort) {
    return (window as Window).__backendPort as number;
  }
  const g = globalThis as typeof globalThis & { __backendPort?: number };
  return g.__backendPort ?? 13400;
}

/**
 * WebUI (browser) mode: no Electron preload, so `window.__backendPort` is not
 * injected. Use same-origin URLs; web-host's static-server handles the reverse
 * proxy / WS upgrade to the backend.
 */
function isWebUiBrowserMode(): boolean {
  return typeof window !== 'undefined' && typeof document !== 'undefined' && !(window as Window).__backendPort;
}

export function getBaseUrl(): string {
  if (isWebUiBrowserMode()) {
    // Same-origin: calls like fetch(`${baseUrl}/api/foo`) resolve to `/api/foo`
    // on whatever host the page was served from.
    return '';
  }
  return `http://127.0.0.1:${getBackendPort()}`;
}

function getWsUrl(): string {
  if (isWebUiBrowserMode()) {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/ws`;
  }
  return `ws://127.0.0.1:${getBackendPort()}/ws`;
}

// ---------------------------------------------------------------------------
// Structured backend error
// ---------------------------------------------------------------------------

/**
 * Error thrown by `httpRequest` when the backend returns a non-2xx response.
 * Carries the structured error envelope (`success: false, error, code`) so
 * callers can branch on `code` without parsing the stringified message.
 *
 * @example
 *   try { await ipcBridge.conversation.sendMessage.invoke(...); }
 *   catch (e) {
 *     if (isBackendHttpError(e) && e.code === 'CONVERSATION_ARCHIVED') { ... }
 *   }
 */
export class BackendHttpError extends Error {
  readonly status: number;
  /** Machine-readable error code from the backend `ErrorResponse.code`, or `''` when parse failed. */
  readonly code: string;
  /** Backend-provided human message from `ErrorResponse.error`, or the raw body when parse failed. */
  readonly backendMessage: string;
  /** Structured backend metadata from `ErrorResponse.details`, when present. */
  readonly details: unknown;
  /** Raw parsed body (object on JSON response, string on text/non-JSON). */
  readonly body: unknown;

  constructor(params: { method: string; path: string; status: number; body: unknown }) {
    const { method, path, status, body } = params;
    let code = '';
    let backendMessage = '';
    let details: unknown;
    if (body && typeof body === 'object') {
      const b = body as { code?: unknown; error?: unknown; details?: unknown };
      if (typeof b.code === 'string') code = b.code;
      if (typeof b.error === 'string') backendMessage = b.error;
      details = b.details;
    } else if (typeof body === 'string') {
      backendMessage = body;
    }
    super(`Backend ${method} ${path} failed (${status}): ${JSON.stringify(body)}`);
    this.name = 'BackendHttpError';
    this.status = status;
    this.code = code;
    this.backendMessage = backendMessage;
    this.details = details;
    this.body = body;
  }
}

export function isBackendHttpError(error: unknown): error is BackendHttpError {
  // Prefer instanceof — fast path in production/bundled contexts.
  if (error instanceof BackendHttpError) return true;
  // Fallback: vite-dev HMR can split the module across chunks, breaking
  // instanceof. Detect by duck-typing on the shape produced by our
  // constructor.
  if (
    error &&
    typeof error === 'object' &&
    'name' in error &&
    (error as { name: unknown }).name === 'BackendHttpError' &&
    'status' in error &&
    typeof (error as { status: unknown }).status === 'number' &&
    'code' in error &&
    typeof (error as { code: unknown }).code === 'string'
  ) {
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// HTTP request helper
// ---------------------------------------------------------------------------

/**
 * Per-request overrides for `httpRequest`.
 *
 * `silentStatuses` lets known-soft failures (e.g. a runtime-scoped lookup
 * returning 404 before the agent has attached) skip the noisy `console.error`
 * and the Sentry breadcrumb that comes with it. The error is still thrown so
 * the caller's existing try/catch keeps working.
 */
export type HttpRequestOptions = {
  silentStatuses?: number[];
  /** Extra request headers merged on top of the default `Content-Type`. */
  headers?: Record<string, string>;
  /** Request timeout in milliseconds (default: 30000 for iOS Safari fix). */
  timeout?: number;
};

const SENSITIVE_LOG_KEY_PATTERN = /api[_-]?key|authorization|auth[_-]?token|access[_-]?token|refresh[_-]?token|secret/i;

function redactForLog(value: unknown, depth = 0): unknown {
  if (depth > 8 || value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactForLog(item, depth + 1));
  }

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
      key,
      SENSITIVE_LOG_KEY_PATTERN.test(key) ? '[REDACTED]' : redactForLog(entry, depth + 1),
    ])
  );
}

const REFRESH_ENDPOINT = '/api/auth/refresh';

/**
 * Paths where a 401 is a genuine credential decision rather than an expired
 * session — refreshing and replaying them would be recursive or nonsensical.
 */
function isAuthEndpoint(path: string): boolean {
  return path.startsWith(REFRESH_ENDPOINT) || path === '/login' || path === '/logout';
}

/**
 * Resolve the Core CSRF double-submit token for the current context.
 *
 * The open-source WebUI removed its CSRF layer with the legacy webserver (M6);
 * a double-submit scheme is slated to return in M7. Until then this is a stub
 * that reports "no token available", so the shared session-refresh primitive
 * (`sessionRefresh.ts`) attaches no `x-csrf-token` header and the backend —
 * which enforces no CSRF check here — accepts the request unchanged.
 *
 * It exists as the single seam every state-changing request would call for its
 * token, so restoring CSRF in M7 (and the aionpro superset, whose backend does
 * enforce the double-submit check) only swaps this body — no caller changes.
 *
 * Returns '' — always, for now.
 */
export function resolveCoreCsrfToken(): string {
  return '';
}

function sendHttpRequest(
  method: string,
  path: string,
  headers: Record<string, string>,
  body?: unknown,
  signal?: AbortSignal
): Promise<Response> {
  const url = `${getBaseUrl()}${path}`;
  return fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: 'include', /* 移动端 Cookie 认证修复：确保浏览器携带 aionui session Cookie */
    signal,
  });
}

/**
 * sendHttpRequest with an AbortController timeout — iOS Safari fix
 * (prevent indefinite hanging on unstable networks). Each call gets a fresh
 * controller so a timed-out request never poisons the 401-refresh replay.
 */
async function sendHttpRequestWithTimeout(
  method: string,
  path: string,
  headers: Record<string, string>,
  body: unknown,
  timeoutMs: number
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await sendHttpRequest(method, path, headers, body, controller.signal);
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error(`[httpBridge] ${method} ${path} → Request timeout after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function httpRequest<T>(
  method: string,
  path: string,
  body?: unknown,
  options?: HttpRequestOptions
): Promise<T> {
  const headers: Record<string, string> = {};

  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  if (options?.headers) {
    Object.assign(headers, options.headers);
  }

  console.debug(
    `[httpBridge] ${method} ${path}`,
    body !== undefined ? JSON.stringify(redactForLog(body)).slice(0, 500) : '(no body)'
  );

  // iOS Safari fix: timeout every request to prevent indefinite hanging on
  // unstable networks (default 30s, overridable via options.timeout).
  const timeoutMs = options?.timeout ?? 30000;
  let response = await sendHttpRequestWithTimeout(method, path, headers, body, timeoutMs);

  // Expired access cookie → 401. Attempt one silent session refresh, then replay
  // the original request — the WebUI half of the #4124 fix. refreshSession() is a
  // no-op outside browser mode and single-flights concurrent 401s into one POST.
  // The auth endpoints themselves are skipped to avoid recursion.
  if (response.status === 401 && !isAuthEndpoint(path)) {
    console.debug(`[httpBridge] ${method} ${path} → 401, attempting session refresh`);
    const refreshed = await refreshSession();
    if (refreshed) {
      console.debug(`[httpBridge] session refreshed, replaying ${method} ${path}`);
      response = await sendHttpRequestWithTimeout(method, path, headers, body, timeoutMs);
    }
  }


  if (!response.ok) {
    // Response body can only be consumed once — read as text, then try JSON
    const rawText = await response.text().catch(() => '');
    let errorBody: unknown;
    try {
      errorBody = JSON.parse(rawText);
    } catch {
      errorBody = rawText;
    }
    if (options?.silentStatuses?.includes(response.status)) {
      console.debug(`[httpBridge] ${method} ${path} → ${response.status} (silenced)`, errorBody);
    } else {
      console.error(`[httpBridge] ${method} ${path} → ${response.status}`, errorBody);
    }
    throw new BackendHttpError({ method, path, status: response.status, body: errorBody });
  }

  console.debug(`[httpBridge] ${method} ${path} → ${response.status} OK`);

  const contentType = response.headers.get('Content-Type');
  if (!contentType?.includes('application/json')) {
    return undefined as T;
  }

  const json = await response.json();
  // Backend wraps in { success, data, ... } — unwrap when present
  if (json && typeof json === 'object' && 'data' in json) {
    return json.data as T;
  }
  return json as T;
}

// ---------------------------------------------------------------------------
// Provider factories (same shape as bridge.buildProvider)
// ---------------------------------------------------------------------------

type ProviderLike<Data, Params> = {
  provider: (handler: (params: Params) => Promise<Data>) => void;
  invoke: Params extends undefined ? () => Promise<Data> : (params: Params) => Promise<Data>;
};

export function withResponseMap<Raw, Mapped, Params>(
  inner: ProviderLike<Raw, Params>,
  map: (data: Raw) => Mapped
): ProviderLike<Mapped, Params> {
  return {
    provider: () => {},
    invoke: (async (params?: Params) => {
      const raw = await (inner.invoke as (p?: Params) => Promise<Raw>)(params);
      return map(raw);
    }) as ProviderLike<Mapped, Params>['invoke'],
  };
}

export function httpGet<Data, Params = undefined>(
  path: string | ((params: Params) => string),
  options?: HttpRequestOptions
): ProviderLike<Data, Params> {
  return {
    provider: () => {},
    invoke: (async (params?: Params) => {
      const resolvedPath = typeof path === 'function' ? path(params!) : path;
      return httpRequest<Data>('GET', resolvedPath, undefined, options);
    }) as ProviderLike<Data, Params>['invoke'],
  };
}

export function httpPost<Data, Params = undefined>(
  path: string | ((params: Params) => string),
  mapBody?: (params: Params) => unknown
): ProviderLike<Data, Params> {
  return {
    provider: () => {},
    invoke: (async (params?: Params) => {
      const resolvedPath = typeof path === 'function' ? path(params!) : path;
      const body = mapBody ? mapBody(params!) : params;
      return httpRequest<Data>('POST', resolvedPath, body);
    }) as ProviderLike<Data, Params>['invoke'],
  };
}

/**
 * Client-side network failure patterns that are safe to retry. HTTP responses
 * (4xx/5xx, incl. 409 busy) are NOT in this set — the server already saw the
 * request, so retrying could duplicate the side effect (e.g. a message POST).
 */
const RETRYABLE_NETWORK_ERROR_PATTERN = /timeout after|load failed|failed to fetch|networkerror|network error|abort/i;

/**
 * POST with client-side retry for flaky mobile links (iOS Safari + VPN).
 *
 * The message-send endpoint is the prime target: on unstable networks the
 * Safari per-host HTTP/1.1 connection pool gets saturated by WebSocket
 * reconnect storms, the fetch() queues client-side, and the 30s httpRequest
 * timeout fires before the request ever leaves the browser — the message is
 * lost and the user sees a send failure. Retrying with a short backoff lets
 * the send land once the pool frees up.
 *
 * Only client-side network failures are retried; any HTTP response is thrown
 * immediately (retrying a 409 busy / 4xx / 5xx cannot help and may duplicate).
 */
export function httpPostRetry<Data, Params = undefined>(
  path: string | ((params: Params) => string),
  mapBody?: (params: Params) => unknown,
  options: { maxAttempts?: number; retryDelayMs?: number; timeout?: number } = {}
): ProviderLike<Data, Params> {
  const { maxAttempts = 3, retryDelayMs = 2000, timeout } = options;
  return {
    provider: () => {},
    invoke: (async (params?: Params) => {
      const resolvedPath = typeof path === 'function' ? path(params!) : path;
      const body = mapBody ? mapBody(params!) : params;
      let lastError: unknown;
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        if (attempt > 0) {
          // Backoff: 2s then 4s — lets the Safari connection pool free up as
          // WS reconnect storms damp out.
          await new Promise((resolve) => setTimeout(resolve, retryDelayMs * attempt));
        }
        try {
          return await httpRequest<Data>('POST', resolvedPath, body, timeout !== undefined ? { timeout } : undefined);
        } catch (error) {
          lastError = error;
          if (error instanceof BackendHttpError) {
            throw error; // server answered — retrying cannot help
          }
          if (error instanceof Error && RETRYABLE_NETWORK_ERROR_PATTERN.test(error.message)) {
            console.warn(
              `[httpBridge] POST ${resolvedPath} attempt ${attempt + 1}/${maxAttempts} failed: ${error.message} — retrying`
            );
            continue;
          }
          throw error;
        }
      }
      throw lastError;
    }) as ProviderLike<Data, Params>['invoke'],
  };
}

export function httpPut<Data, Params = undefined>(
  path: string | ((params: Params) => string),
  mapBody?: (params: Params) => unknown,
  mapHeaders?: (params: Params) => Record<string, string> | undefined
): ProviderLike<Data, Params> {
  return {
    provider: () => {},
    invoke: (async (params?: Params) => {
      const resolvedPath = typeof path === 'function' ? path(params!) : path;
      const body = mapBody ? mapBody(params!) : params;
      const headers = mapHeaders ? mapHeaders(params!) : undefined;
      return httpRequest<Data>('PUT', resolvedPath, body, headers ? { headers } : undefined);
    }) as ProviderLike<Data, Params>['invoke'],
  };
}

export function httpPatch<Data, Params = undefined>(
  path: string | ((params: Params) => string),
  mapBody?: (params: Params) => unknown
): ProviderLike<Data, Params> {
  return {
    provider: () => {},
    invoke: (async (params?: Params) => {
      const resolvedPath = typeof path === 'function' ? path(params!) : path;
      const body = mapBody ? mapBody(params!) : params;
      return httpRequest<Data>('PATCH', resolvedPath, body);
    }) as ProviderLike<Data, Params>['invoke'],
  };
}

export function httpDelete<Data, Params = undefined>(
  path: string | ((params: Params) => string)
): ProviderLike<Data, Params> {
  return {
    provider: () => {},
    invoke: (async (params?: Params) => {
      const resolvedPath = typeof path === 'function' ? path(params!) : path;
      return httpRequest<Data>('DELETE', resolvedPath);
    }) as ProviderLike<Data, Params>['invoke'],
  };
}

/**
 * Stub provider for features not yet implemented in the backend.
 * Returns a sensible default value and logs a warning.
 */
export function stubProvider<Data, Params = undefined>(name: string, defaultValue: Data): ProviderLike<Data, Params> {
  return {
    provider: () => {},
    invoke: (async (_params?: Params) => {
      console.warn(`[httpBridge] stub: ${name} not yet implemented in backend`);
      return defaultValue;
    }) as ProviderLike<Data, Params>['invoke'],
  };
}

// ---------------------------------------------------------------------------
// WebSocket singleton
// ---------------------------------------------------------------------------

type WsCallback = (data: unknown) => void;
const REALTIME_RECONNECTED_EVENT = 'realtime.reconnected';
const wsListeners = new Map<string, Set<WsCallback>>();
let ws: WebSocket | null = null;
let wsReconnectTimer: ReturnType<typeof setTimeout> | null = null;
let wsReconnectAttempt = 0;
let wsHasOpened = false;
// Timestamp of the last successful socket open. The reconnect backoff resets
// only when the previous connection was stable — see the close handler.
let wsOpenedAt = 0;

function dispatchWsEvent(eventName: string, payload: unknown): void {
  const handlers = wsListeners.get(eventName);
  if (!handlers) return;
  for (const handler of handlers) {
    try {
      handler(payload);
    } catch {
      /* never crash listener */
    }
  }
}

// iOS Safari fix: never hold a WebSocket while the login page is active.
// Safari's per-host HTTP/1.1 connection pool is small (~6); lingering WS
// connections (reconnect storms, background/foreground churn) exhaust it and
// fetch('/login') then queues client-side forever — the login button spins
// and the request never reaches the server. Subscriptions registered while
// on the login page stay in wsListeners and connect on the first post-login
// ensureWs() call (conversation runtime view / wsSend / wsEmitter.on).
function isLoginPage(): boolean {
  return window.location.pathname === '/login' || window.location.hash.includes('/login');
}

function ensureWs(): void {
  if (isLoginPage()) {
    return;
  }
  if (typeof window === 'undefined') {
    console.debug('[ensureWs] skipped: no window');
    return;
  }
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    console.debug('[ensureWs] skipped: already open/connecting, readyState=', ws.readyState);
    return;
  }

  const url = getWsUrl();
  console.debug('[ensureWs] connecting to', url);
  try {
    ws = new WebSocket(url);
  } catch (e) {
    console.error('[ensureWs] WebSocket constructor threw:', e);
    scheduleWsReconnect();
    return;
  }

  const current = ws;

  current.addEventListener('open', () => {
    console.debug('[ensureWs] CONNECTED');
    const isReconnect = wsHasOpened;
    wsHasOpened = true;
    wsOpenedAt = Date.now();
    if (isReconnect) {
      dispatchWsEvent(REALTIME_RECONNECTED_EVENT, { timestamp: Date.now() });
    }
  });

  current.addEventListener('close', (e) => {
    console.debug('[ensureWs] CLOSED code=' + e.code + ' reason=' + e.reason);
    if (ws === current) ws = null;
    if (e.code === WS_CLOSE_POLICY_VIOLATION) {
      // Auth policy violation (expired/missing session). Blindly reconnecting with
      // the same dead cookie is the #4124 loop — refresh once and only reconnect if
      // it succeeds. On failure the realtime stream stays down until re-auth;
      // browser.ts's bridge socket drives the /login redirect.
      void handleWsAuthClose();
      return;
    }
    // Reset the backoff ONLY when the previous connection was stable for a
    // while — a socket that opens and dies within seconds must keep the
    // growing delay, otherwise the reconnect storm self-sustains at 1s cadence
    // and keeps Safari's connection pool full (fetch() calls then queue
    // client-side and hit their timeout).
    if (wsOpenedAt !== 0 && Date.now() - wsOpenedAt >= 30000) {
      wsReconnectAttempt = 0;
    }
    wsOpenedAt = 0;
    scheduleWsReconnect();
  });

  current.addEventListener('error', (e) => {
    console.error('[ensureWs] ERROR', e);
    current.close();
  });

  current.addEventListener('message', (event: MessageEvent) => {
    try {
      const msg = JSON.parse(event.data as string) as {
        name?: string;
        event?: string;
        data?: unknown;
        payload?: unknown;
      };
      const eventName = msg.name ?? msg.event;
      const payload = msg.data ?? msg.payload;
      console.debug('[WS:msg]', eventName, JSON.stringify(payload).slice(0, 200));
      if (eventName) {
        dispatchWsEvent(eventName, payload);
      }
    } catch {
      // ignore non-JSON
    }
  });
}

/**
 * iOS Safari multi-tab mitigation: a hidden background tab keeps its WS alive
 * while its JS is frozen, so the socket only burns a Safari per-host HTTP/1.1
 * connection-pool slot (~6 total) for nothing. HOWEVER — on a 5G link the
 * user switches apps / pulls the notification shade / briefly locks the phone
 * constantly, firing visibilitychange hidden→visible repeatedly. Closing the
 * socket on every hide produced a high-frequency reconnect loop (connections
 * living 50ms-20s, backoff never reached its 30s reset threshold, pool churn
 * worse than the original disease). So: on hide we only CANCEL the pending
 * reconnect timer (a frozen background tab must not fire its backoff when
 * Safari unfreezes it); the socket itself stays open and keeps working across
 * short app switches. On show we schedule through the normal backoff path —
 * if the socket died while hidden, the reconnect uses the exponential delay;
 * if it is still OPEN, scheduleWsReconnect() is a no-op (timer guard).
 */
function installVisibilityWsRelease(): void {
  if (typeof document === 'undefined') return;
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      if (wsReconnectTimer) {
        clearTimeout(wsReconnectTimer);
        wsReconnectTimer = null;
      }
    } else {
      scheduleWsReconnect();
    }
  });
}

function scheduleWsReconnect(): void {
  if (isLoginPage()) return;
  if (wsReconnectTimer) return;
  const delay = Math.min(1000 * Math.pow(2, wsReconnectAttempt), 30000);
  wsReconnectAttempt++;
  wsReconnectTimer = setTimeout(() => {
    wsReconnectTimer = null;
    ensureWs();
  }, delay);
}

/**
 * Handle a realtime socket closed for auth policy violation (code 1008): attempt
 * one shared session refresh, then reconnect only if the session was renewed.
 * A failed refresh means the session is truly dead — we stop rather than loop.
 */
async function handleWsAuthClose(): Promise<void> {
  const refreshed = await refreshSession();
  if (refreshed) {
    wsReconnectAttempt = 0;
    ensureWs();
  }
}

/**
 * Send an outbound frame over the shared WS singleton, wrapped in the realtime
 * envelope `{ name, data }` (backend routes by `name`; the fs monitor uses
 * `name === "fs"`, see stage-1 protocol.md v3).
 *
 * Ordered-stream semantics: if the socket is not OPEN the frame is **dropped**
 * (never buffered). The caller re-declares full state on reconnect (the monitor
 * client zeroes `current` and re-subscribes via `realtime.reconnected`), so a
 * dropped outbound never leaves an undetectable gap. Returns `true` when the
 * frame was handed to the socket.
 */
export function wsSend(name: string, data: unknown): boolean {
  ensureWs();
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return false;
  }
  try {
    ws.send(JSON.stringify({ name, data }));
    return true;
  } catch (e) {
    console.error('[wsSend] send failed:', e);
    return false;
  }
}

// ---------------------------------------------------------------------------
// Emitter factory (same shape as bridge.buildEmitter)
// ---------------------------------------------------------------------------

type EmitterLike<Params> = {
  on: (callback: Params extends undefined ? () => void : (params: Params) => void) => () => void;
  emit: Params extends undefined ? () => void : (params: Params) => void;
};

export function wsEmitter<Params = undefined>(eventName: string): EmitterLike<Params> {
  return {
    on: (callback: (params: Params) => void) => {
      ensureWs();
      if (!wsListeners.has(eventName)) {
        wsListeners.set(eventName, new Set());
      }
      const cb = callback as WsCallback;
      wsListeners.get(eventName)!.add(cb);
      return () => {
        wsListeners.get(eventName)?.delete(cb);
      };
    },
    emit: (() => {}) as EmitterLike<Params>['emit'],
  };
}

export function wsMappedEmitter<Params = undefined>(
  eventName: string,
  transform: (raw: unknown) => Params
): EmitterLike<Params> {
  const inner = wsEmitter<unknown>(eventName);
  return {
    on: (callback: (params: Params) => void) => {
      return inner.on((raw) => {
        callback(transform(raw));
      });
    },
    emit: (() => {}) as EmitterLike<Params>['emit'],
  };
}

/**
 * Stub emitter for events not yet implemented in the backend.
 */
export function stubEmitter<Params = undefined>(_name: string): EmitterLike<Params> {
  return {
    on: () => () => {},
    emit: (() => {}) as EmitterLike<Params>['emit'],
  };
}

// Module-level install: release the WS slot while the tab is hidden
// (multi-tab Safari pool mitigation — see installVisibilityWsRelease above).
installVisibilityWsRelease();
