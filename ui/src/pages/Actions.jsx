import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Power,
    Square,
    RefreshCw,
    FolderOpen,
    Globe,
    KeyRound,
    Package,
} from 'lucide-react';
import { useStatus } from '../ipc/hooks.js';
import { local } from '../ipc/client.js';

// Actions are bucketed so the most-common operations sit on top and the
// destructive / re-pair ones live further down. A shared ActionRow renders
// them with icon + label + description + button.

function ActionRow({ icon: Icon, title, desc, action, label = 'Run', danger }) {
    const [busy, setBusy] = useState(false);
    const [feedback, setFeedback] = useState(null);

    async function onClick() {
        if (busy) return;
        setBusy(true);
        setFeedback(null);
        try {
            await action();
            setFeedback({ ok: true, msg: 'Done' });
        } catch (err) {
            setFeedback({ ok: false, msg: err.message || 'Failed' });
        } finally {
            setBusy(false);
            setTimeout(() => setFeedback(null), 3000);
        }
    }

    return (
        <div className="action">
            <div className="action__icon">
                <Icon size={18} />
            </div>
            <div className="action__body">
                <div className="action__title">{title}</div>
                <div className="action__desc">{desc}</div>
            </div>
            <div className="action__buttons">
                {feedback && (
                    <span
                        className={
                            'action__feedback ' +
                            (feedback.ok ? 'action__feedback--ok' : 'action__feedback--err')
                        }
                    >
                        {feedback.msg}
                    </span>
                )}
                <button
                    type="button"
                    className={'btn' + (danger ? ' btn--danger' : '')}
                    onClick={onClick}
                    disabled={busy}
                >
                    {busy ? '…' : label}
                </button>
            </div>
        </div>
    );
}

export default function Actions() {
    const { status } = useStatus(5000);
    const navigate = useNavigate();
    const dashboardUrl = status?.server_url
        ? status.server_url.replace(/^wss?:\/\//, 'https://').replace(/\/agent$/, '')
        : '';

    return (
        <div className="page">
            <header className="page__header">
                <div>
                    <h1 className="page__title">Actions</h1>
                    <p className="page__sub muted">Service controls, recovery, and quick-open shortcuts.</p>
                </div>
            </header>

            <section className="card card--padded">
                <div className="action-group__heading">Service</div>
                <ActionRow
                    icon={RefreshCw}
                    title="Restart agent"
                    desc="Stops then starts the ServerKitAgent service. Use this after re-pairing or changing config."
                    action={local.serviceRestart}
                    label="Restart"
                />
                <ActionRow
                    icon={Power}
                    title="Start agent"
                    desc="Starts the service if it's not running."
                    action={local.serviceStart}
                    label="Start"
                />
                <ActionRow
                    icon={Square}
                    title="Stop agent"
                    desc="Stops the service. The console window stays open."
                    action={local.serviceStop}
                    label="Stop"
                    danger
                />
            </section>

            <section className="card card--padded">
                <div className="action-group__heading">Quick open</div>
                <ActionRow
                    icon={FolderOpen}
                    title="Open log folder"
                    desc="Opens C:\\ProgramData\\ServerKit\\Agent\\logs in Explorer."
                    action={() => local.open({ path: 'C:\\ProgramData\\ServerKit\\Agent\\logs' })}
                    label="Open"
                />
                <ActionRow
                    icon={Globe}
                    title="Open dashboard"
                    desc={dashboardUrl ? `Opens ${dashboardUrl} in your browser.` : 'Opens the panel URL once the agent is paired.'}
                    action={() => local.open({ url: dashboardUrl })}
                    label="Open"
                />
            </section>

            <section className="card card--padded">
                <div className="action-group__heading">Pairing</div>
                <ActionRow
                    icon={KeyRound}
                    title="Re-pair this server"
                    desc="Reopens the pairing wizard in this window. Useful when the panel URL changes (e.g. switching tunnels) or to rotate credentials."
                    action={async () => { navigate('/pair'); }}
                    label="Open wizard"
                />
            </section>

            <section className="card card--padded">
                <div className="action-group__heading">Support</div>
                <ActionRow
                    icon={Package}
                    title="Generate diagnostic bundle"
                    desc="Zips agent.log, recent backups, redacted config, events, and system info to your Desktop. Safe to share — credentials are stripped."
                    action={async () => {
                        const res = await local.diag();
                        if (res?.path) {
                            // Open the parent folder so the user sees the
                            // newly-created zip in Explorer rather than
                            // opening the zip itself.
                            const parent = res.path.replace(/[\\/][^\\/]*$/, '');
                            await local.open({ path: parent });
                        }
                    }}
                    label="Generate"
                />
            </section>
        </div>
    );
}
