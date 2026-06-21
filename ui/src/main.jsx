import { StrictMode, Component } from 'react';
import { createRoot } from 'react-dom/client';
import { HashRouter } from 'react-router-dom';
import App from './App.jsx';
import './styles/main.scss';

// 1.6.2 had a class of "blank #root" bug reports where a render exception
// in App or any provider unmounted the index.html splash and left no
// fallback. The user saw nothing and we got a navReady signal that lied —
// the bundle ran, the listener fired, and *then* React crashed on mount.
// This boundary keeps the window from going blank on render errors and
// echoes the message back to the WebView2 host log via window.agentLog.
class RootErrorBoundary extends Component {
    state = { error: null };
    static getDerivedStateFromError(error) {
        return { error };
    }
    componentDidCatch(error, info) {
        try {
            if (window.agentLog) {
                window.agentLog('error', 'react root: ' + (error && error.stack ? error.stack : String(error)));
            }
        } catch { /* ignore — host bridge may not be present */ }
    }
    render() {
        if (this.state.error) {
            const msg = this.state.error && this.state.error.message
                ? this.state.error.message
                : String(this.state.error);
            return (
                <div style={{
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: '24px',
                    background: '#09090b',
                    color: '#f4f4f5',
                    fontFamily: 'Segoe UI, system-ui, sans-serif',
                    gap: '12px',
                }}>
                    <div style={{ fontSize: 16, fontWeight: 600 }}>ServerKit Agent failed to start</div>
                    <div style={{ fontSize: 13, color: '#a1a1aa', maxWidth: 600, textAlign: 'center' }}>
                        Right-click anywhere and choose <strong>Inspect</strong> to see the full error in DevTools.
                        The message below has also been written to <code>desktop.log</code>.
                    </div>
                    <pre style={{
                        fontSize: 12,
                        color: '#fca5a5',
                        background: '#18181b',
                        border: '1px solid #27272a',
                        borderRadius: 6,
                        padding: '12px 16px',
                        maxWidth: '80%',
                        overflow: 'auto',
                        whiteSpace: 'pre-wrap',
                    }}>{msg}</pre>
                </div>
            );
        }
        return this.props.children;
    }
}

createRoot(document.getElementById('root')).render(
    <StrictMode>
        <RootErrorBoundary>
            <HashRouter>
                <App />
            </HashRouter>
        </RootErrorBoundary>
    </StrictMode>
);
