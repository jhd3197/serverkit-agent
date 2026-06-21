import { useStatus } from '../ipc/hooks.js';

export default function About() {
    const { status } = useStatus(5000);
    return (
        <div className="page">
            <header className="page__header">
                <h1 className="page__title">About</h1>
                <p className="page__sub muted">ServerKit Agent Console</p>
            </header>
            <div className="card">
                <div className="info-row">
                    <span className="info-row__label">Version</span>
                    <span className="info-row__value">{status?.version || '—'}</span>
                </div>
                <div className="info-row">
                    <span className="info-row__label">Agent ID</span>
                    <span className="info-row__value info-row__value--mono">{status?.agent_id || '—'}</span>
                </div>
                <div className="info-row">
                    <span className="info-row__label">Hostname</span>
                    <span className="info-row__value">{status?.agent_name || '—'}</span>
                </div>
            </div>
            <div className="card empty-state">
                Unpair and Uninstall actions will land here in the next milestone.
            </div>
        </div>
    );
}
