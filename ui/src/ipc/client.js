// Tiny client for the agent's local IPC server. Always 127.0.0.1 — the IPC
// server refuses non-loopback binds — and gates every endpoint except
// /health behind a bearer token. We fetch the token from the in-process
// asset server (/local/ipc-token), which reads it off disk: the React UI
// can't read filesystem paths, but the Go console process running it can.

const DEFAULT_PORT = 19780;

// Resolve the IPC base URL. The agent UI runs in WebView2 served from
// 127.0.0.1:<random>, so we can't get the IPC port from the document origin.
// We accept an override via an env var (Vite injects it at build time) and
// otherwise fall back to the default port baked into the agent's config.
const PORT =
    Number(import.meta.env.VITE_AGENT_IPC_PORT) ||
    Number(window.__SERVERKIT_IPC_PORT__) ||
    DEFAULT_PORT;

const BASE = `http://127.0.0.1:${PORT}`;

// Cache the token in-module so we don't re-fetch on every IPC call.
// Refresh on 401 so a token rotation (rare; only if the file is wiped
// and the agent restarts) gets picked up without a UI reload.
let _tokenPromise = null;

async function fetchToken() {
    const res = await fetch('/local/ipc-token');
    if (!res.ok) {
        // 503 means "agent service not running yet" — propagate so the
        // hook can decide whether to retry.
        const err = new Error(`token fetch failed: ${res.status}`);
        err.status = res.status;
        throw err;
    }
    const json = await res.json();
    return json.token;
}

async function ipcToken() {
    if (!_tokenPromise) {
        _tokenPromise = fetchToken().catch((err) => {
            // Don't cache failure — next call will retry.
            _tokenPromise = null;
            throw err;
        });
    }
    return _tokenPromise;
}

function invalidateToken() {
    _tokenPromise = null;
}

async function authedHeaders(extra) {
    let headers = { Accept: 'application/json', ...(extra || {}) };
    try {
        const tok = await ipcToken();
        if (tok) headers.Authorization = `Bearer ${tok}`;
    } catch {
        // Fall through with no Authorization header. /health still works
        // and any other endpoint will return 401, which the hooks already
        // surface as "agent unreachable".
    }
    return headers;
}

async function get(path) {
    const headers = await authedHeaders();
    let res = await fetch(`${BASE}${path}`, { method: 'GET', headers });
    if (res.status === 401) {
        // Token might be stale (file rewritten on agent restart). One
        // retry with a freshly fetched token before bubbling the error.
        invalidateToken();
        const retryHeaders = await authedHeaders();
        res = await fetch(`${BASE}${path}`, { method: 'GET', headers: retryHeaders });
    }
    if (!res.ok) {
        const text = await res.text().catch(() => '');
        throw new Error(`IPC ${path} ${res.status}: ${text || res.statusText}`);
    }
    return res.json();
}

async function post(path, body) {
    const headers = await authedHeaders({ 'Content-Type': 'application/json' });
    let res = await fetch(`${BASE}${path}`, {
        method: 'POST',
        headers,
        body: body ? JSON.stringify(body) : null,
    });
    if (res.status === 401) {
        invalidateToken();
        const retryHeaders = await authedHeaders({ 'Content-Type': 'application/json' });
        res = await fetch(`${BASE}${path}`, {
            method: 'POST',
            headers: retryHeaders,
            body: body ? JSON.stringify(body) : null,
        });
    }
    if (!res.ok) {
        const text = await res.text().catch(() => '');
        throw new Error(`IPC ${path} ${res.status}: ${text || res.statusText}`);
    }
    return res.json();
}

export const ipc = {
    health: () => get('/health'),
    status: () => get('/status'),
    metricsHistory: () => get('/metrics/history'),
    events: (since = 0) => get(`/events${since ? `?since=${since}` : ''}`),
    connection: () => get('/connection'),
    logs: (lines = 200) => get(`/logs?lines=${lines}`),
    clearLogs: () => post('/logs/clear'),
    restart: () => post('/restart'),
};

// "local" calls hit the asset server in the *console process*, not the
// agent service. These are the operations that have to happen even when
// the agent service is down (Start the service, Re-pair) or that need an
// interactive Windows session (Open in Explorer / browser).
async function localCall(path, body) {
    const res = await fetch(path, {
        method: 'POST',
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : null,
    });
    if (!res.ok) {
        let msg = res.statusText;
        try {
            const j = await res.json();
            if (j && j.error) msg = j.error;
        } catch { /* keep statusText */ }
        const err = new Error(msg);
        err.status = res.status;
        throw err;
    }
    return res.json();
}

async function localGet(path) {
    const res = await fetch(path);
    if (!res.ok) {
        const err = new Error(res.statusText);
        err.status = res.status;
        throw err;
    }
    return res.json();
}

export const local = {
    serviceStart: () => localCall('/local/service/start'),
    serviceStop: () => localCall('/local/service/stop'),
    serviceRestart: () => localCall('/local/service/restart'),
    open: (target) => localCall('/local/open', target),
    repair: () => localCall('/local/wizard'),
    diag: () => localCall('/local/diag'),
    // status reads config.yaml in the console process so we can route the
    // wizard correctly even when the agent service isn't running (which is
    // the default state on a fresh install — no config, no service).
    status: () => localGet('/local/status'),
    pairStart: (panelUrl, serverName) =>
        localCall('/local/pair/start', { panel_url: panelUrl, server_name: serverName }),
    pairState: () => localGet('/local/pair/state'),
    pairCancel: () => localCall('/local/pair/cancel'),
    // The single-string entry path. The agent decodes the string, calls
    // /api/v1/servers/register on the panel, and lands on the same
    // "claimed" state the pair-code flow ends in — so polling /state
    // works unchanged.
    pairConnectionString: (connectionString) =>
        localCall('/local/pair/connection-string', { connection_string: connectionString }),
};
