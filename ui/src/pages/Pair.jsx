import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Copy, Check, Server, ArrowRight, Loader2, CircleCheck, AlertTriangle } from 'lucide-react';
import { local } from '../ipc/client.js';

// Three-stage React port of the legacy walk wizard. The actual pairing
// protocol still runs in Go via internal/pairdriver — this component just
// drives the form, kicks off /local/pair/start, polls /local/pair/state,
// and renders whatever stage the backend reports.

function CopyValue({ value, large }) {
    const [copied, setCopied] = useState(false);
    return (
        <div className={'copy-value ' + (large ? 'copy-value--large' : '')}>
            <span className="copy-value__text">{value}</span>
            <button
                type="button"
                className="copy-btn"
                onClick={() => {
                    navigator.clipboard.writeText(value);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 1200);
                }}
                title={copied ? 'Copied!' : 'Copy'}
            >
                {copied ? <Check size={16} /> : <Copy size={16} />}
            </button>
        </div>
    );
}

function FormStage({ onConnectionString, onPairCode, busy, defaultName }) {
    // Default to the connection-string tab — that's the modern entry path
    // (one paste, one click). The legacy pair-code form stays available
    // for users who already started from the panel's "Pair existing
    // agent" tab, or who can't paste from clipboard for some reason.
    const [mode, setMode] = useState('connection-string');
    const [connString, setConnString] = useState('');
    const [panelUrl, setPanelUrl] = useState('');
    const [name, setName] = useState(defaultName || '');
    const [error, setError] = useState('');

    function submitConnString(e) {
        e.preventDefault();
        const trimmed = connString.trim();
        if (!trimmed) {
            setError('Paste the connection string from your panel.');
            return;
        }
        if (!trimmed.startsWith('sk1://')) {
            setError('That doesn’t look like a connection string. Generate one from the panel’s Add Server screen.');
            return;
        }
        setError('');
        onConnectionString(trimmed);
    }

    function submitPairCode(e) {
        e.preventDefault();
        if (!panelUrl.trim()) {
            setError('Panel URL is required');
            return;
        }
        setError('');
        onPairCode(panelUrl.trim(), name.trim());
    }

    return (
        <div className="wizard">
            <div className="wizard__head">
                <div className="wizard__brand">
                    <Server size={28} />
                </div>
                <h1 className="wizard__title">Pair this server</h1>
                <p className="wizard__sub">Connect this machine to your ServerKit panel.</p>
            </div>

            <div className="wizard__tabs" role="tablist">
                <button
                    type="button"
                    role="tab"
                    aria-selected={mode === 'connection-string'}
                    className={'wizard__tab ' + (mode === 'connection-string' ? 'is-active' : '')}
                    onClick={() => { setMode('connection-string'); setError(''); }}
                >
                    Connection string
                </button>
                <button
                    type="button"
                    role="tab"
                    aria-selected={mode === 'pair-code'}
                    className={'wizard__tab ' + (mode === 'pair-code' ? 'is-active' : '')}
                    onClick={() => { setMode('pair-code'); setError(''); }}
                >
                    Pair code
                </button>
            </div>

            {mode === 'connection-string' ? (
                <form onSubmit={submitConnString} className="wizard__body">
                    <label className="field">
                        <span className="field__label">Connection string</span>
                        <textarea
                            className="field__input field__input--mono"
                            rows={4}
                            placeholder="sk1://panel.example.com/sk_reg_..."
                            value={connString}
                            onChange={(e) => setConnString(e.target.value)}
                            autoFocus
                            spellCheck={false}
                        />
                        <span className="field__hint">
                            Generate it in the panel: <strong>Add Server → Connection string</strong>.
                            The hostname of this machine becomes the server name automatically.
                        </span>
                    </label>

                    {error && <div className="banner banner--warn">{error}</div>}

                    <button type="submit" className="btn btn--primary btn--large" disabled={busy}>
                        {busy ? (
                            <><Loader2 size={16} className="spin" /> Connecting…</>
                        ) : (
                            <>Connect <ArrowRight size={16} /></>
                        )}
                    </button>
                </form>
            ) : (
                <form onSubmit={submitPairCode} className="wizard__body">
                    <label className="field">
                        <span className="field__label">Panel URL</span>
                        <input
                            type="text"
                            className="field__input"
                            placeholder="https://panel.example.com"
                            value={panelUrl}
                            onChange={(e) => setPanelUrl(e.target.value)}
                            autoFocus
                            spellCheck={false}
                        />
                        <span className="field__hint">The full URL of your ServerKit control panel.</span>
                    </label>

                    <label className="field">
                        <span className="field__label">Server name <span className="muted">(optional)</span></span>
                        <input
                            type="text"
                            className="field__input"
                            placeholder="Defaults to hostname"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            spellCheck={false}
                        />
                        <span className="field__hint">How this machine appears in your panel.</span>
                    </label>

                    {error && <div className="banner banner--warn">{error}</div>}

                    <button type="submit" className="btn btn--primary btn--large" disabled={busy}>
                        {busy ? (
                            <><Loader2 size={16} className="spin" /> Connecting…</>
                        ) : (
                            <>Connect <ArrowRight size={16} /></>
                        )}
                    </button>
                </form>
            )}
        </div>
    );
}

function PairCodeStage({ state, onCancel }) {
    return (
        <div className="wizard">
            <div className="wizard__head">
                <h1 className="wizard__title">Enter both values in your panel</h1>
                <p className="wizard__sub">
                    On your panel, open <strong>Add Server → Pair existing agent</strong>, then type these in.
                </p>
            </div>

            <div className="wizard__body">
                <div className="pair-display">
                    <div className="pair-display__label">Pair code</div>
                    <CopyValue value={state.code_formatted || state.code} large />
                </div>
                <div className="pair-display">
                    <div className="pair-display__label">Passphrase</div>
                    <CopyValue value={state.passphrase} />
                </div>

                <div className="wizard__status">
                    <Loader2 size={14} className="spin" />
                    <span>Waiting for the panel to claim this server…</span>
                </div>

                <button type="button" className="btn" onClick={onCancel}>
                    Cancel
                </button>
            </div>
        </div>
    );
}

function DoneStage({ state, onContinue }) {
    return (
        <div className="wizard">
            <div className="wizard__head">
                <div className="wizard__brand wizard__brand--ok">
                    <CircleCheck size={28} />
                </div>
                <h1 className="wizard__title">Successfully paired</h1>
                <p className="wizard__sub">
                    This machine is now connected to ServerKit as <strong>{state.server_name || 'this server'}</strong>.
                </p>
            </div>

            <div className="wizard__body">
                <p className="muted" style={{ textAlign: 'center', margin: 0 }}>
                    The agent service has been restarted with the new configuration.
                </p>
                <button type="button" className="btn btn--primary btn--large" onClick={onContinue}>
                    Open console <ArrowRight size={16} />
                </button>
            </div>
        </div>
    );
}

function ErrorStage({ state, onRetry }) {
    return (
        <div className="wizard">
            <div className="wizard__head">
                <div className="wizard__brand wizard__brand--err">
                    <AlertTriangle size={28} />
                </div>
                <h1 className="wizard__title">Pairing failed</h1>
            </div>

            <div className="wizard__body">
                <div className="banner banner--warn">{state.error || 'Unknown error'}</div>
                <button type="button" className="btn btn--primary btn--large" onClick={onRetry}>
                    Try again
                </button>
            </div>
        </div>
    );
}

export default function Pair() {
    const navigate = useNavigate();
    const [state, setState] = useState({ state: 'idle' });
    const [busy, setBusy] = useState(false);
    const pollRef = useRef(null);

    // Poll /local/pair/state once a second while the wizard is open. The
    // initial fetch on mount also covers the case where the user closed and
    // reopened the console mid-pairing — we land back on the right stage.
    useEffect(() => {
        let cancelled = false;
        async function tick() {
            try {
                const s = await local.pairState();
                if (!cancelled) setState(s);
            } catch {
                // Asset server is in the same process — if it's gone, the
                // window is closing anyway.
            }
        }
        tick();
        pollRef.current = setInterval(tick, 1000);
        return () => {
            cancelled = true;
            clearInterval(pollRef.current);
        };
    }, []);

    async function handlePairCode(panelUrl, name) {
        setBusy(true);
        try {
            await local.pairStart(panelUrl, name);
            const s = await local.pairState();
            setState(s);
        } catch (err) {
            setState({ state: 'error', error: err.message });
        } finally {
            setBusy(false);
        }
    }

    async function handleConnectionString(value) {
        setBusy(true);
        try {
            await local.pairConnectionString(value);
            // Optimistic transition: the agent's poll loop will catch up
            // and report claimed/error within a second or two, but moving
            // off the form right away keeps the UI from feeling stuck.
            setState({ state: 'enrolling' });
        } catch (err) {
            setState({ state: 'error', error: err.message });
        } finally {
            setBusy(false);
        }
    }

    async function handleCancel() {
        await local.pairCancel();
        setState({ state: 'idle' });
    }

    if (state.state === 'claimed') {
        return <DoneStage state={state} onContinue={() => navigate('/overview')} />;
    }
    if (state.state === 'error') {
        return <ErrorStage state={state} onRetry={() => setState({ state: 'idle' })} />;
    }
    if (state.state === 'enrolling' || state.state === 'waiting') {
        // The pair-code wizard shows a code+passphrase pane, but the
        // connection-string flow has nothing for the user to copy at this
        // stage — it's just "wait for /register to come back." Pick the
        // pane based on whether we have a code yet.
        if (state.code || state.code_formatted) {
            return <PairCodeStage state={state} onCancel={handleCancel} />;
        }
        return <ConnectingStage onCancel={handleCancel} />;
    }
    return (
        <FormStage
            onConnectionString={handleConnectionString}
            onPairCode={handlePairCode}
            busy={busy}
        />
    );
}

function ConnectingStage({ onCancel }) {
    return (
        <div className="wizard">
            <div className="wizard__head">
                <h1 className="wizard__title">Registering this server…</h1>
                <p className="wizard__sub">
                    Talking to the panel and saving credentials. This usually takes a few seconds.
                </p>
            </div>
            <div className="wizard__body">
                <div className="wizard__status">
                    <Loader2 size={14} className="spin" />
                    <span>Waiting for the panel to confirm registration…</span>
                </div>
                <button type="button" className="btn" onClick={onCancel}>
                    Cancel
                </button>
            </div>
        </div>
    );
}
