import { useMemo, useState } from 'react';
import {
    Power,
    Square,
    RefreshCw,
    Plug,
    PlugZap,
    AlertTriangle,
    XCircle,
    Info,
} from 'lucide-react';
import { useEvents } from '../ipc/hooks.js';

// Maps backend event Kind → React icon. Anything unrecognized falls through
// to the Info bubble so future kinds render gracefully without a UI patch.
const KIND_ICON = {
    service_start: Power,
    service_stop: Square,
    restart_requested: RefreshCw,
    ws_connected: PlugZap,
    ws_disconnected: Plug,
    ws_reconnecting: RefreshCw,
    auth_failed: XCircle,
    error: AlertTriangle,
    info: Info,
};

const SEVERITIES = ['all', 'info', 'warn', 'error'];

function formatRelative(ts) {
    const diffMs = Date.now() - ts;
    const sec = Math.floor(diffMs / 1000);
    if (sec < 5) return 'just now';
    if (sec < 60) return `${sec}s ago`;
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min}m ago`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr}h ago`;
    const day = Math.floor(hr / 24);
    return `${day}d ago`;
}

function formatAbsolute(ts) {
    const d = new Date(ts);
    return d.toLocaleString();
}

function EventRow({ event }) {
    const Icon = KIND_ICON[event.kind] || Info;
    return (
        <li className={`event event--${event.sev || 'info'}`}>
            <div className="event__icon">
                <Icon size={16} />
            </div>
            <div className="event__body">
                <div className="event__msg">{event.msg}</div>
                {event.meta && Object.keys(event.meta).length > 0 && (
                    <div className="event__meta">
                        {Object.entries(event.meta).map(([k, v]) => (
                            <span key={k} className="event__meta-item">
                                <strong>{k}:</strong> {String(v)}
                            </span>
                        ))}
                    </div>
                )}
            </div>
            <time className="event__time" title={formatAbsolute(event.t)}>
                {formatRelative(event.t)}
            </time>
        </li>
    );
}

export default function Activity() {
    const { events, error } = useEvents(3000);
    const [filter, setFilter] = useState('all');

    const visible = useMemo(() => {
        const list = filter === 'all'
            ? events
            : events.filter((e) => (e.sev || 'info') === filter);
        // Newest first reads better as a timeline.
        return [...list].reverse();
    }, [events, filter]);

    return (
        <div className="page">
            <header className="page__header">
                <div>
                    <h1 className="page__title">Activity</h1>
                    <p className="page__sub muted">
                        Lifecycle events from this agent — service starts, connection changes, and operator actions.
                    </p>
                </div>
                <div className="filter-group">
                    {SEVERITIES.map((sev) => (
                        <button
                            key={sev}
                            type="button"
                            className={
                                'chip' + (filter === sev ? ' chip--active' : '')
                            }
                            onClick={() => setFilter(sev)}
                        >
                            {sev}
                        </button>
                    ))}
                </div>
            </header>

            {error && (
                <div className="banner banner--warn">
                    Can't reach the agent IPC server. ({error})
                </div>
            )}

            <section className="card card--padded">
                {visible.length === 0 ? (
                    <div className="empty-state">
                        {events.length === 0
                            ? 'No events yet — they\'ll appear here as the agent connects, restarts, or hits errors.'
                            : `Nothing matches the “${filter}” filter.`}
                    </div>
                ) : (
                    <ul className="event-list">
                        {visible.map((ev) => (
                            <EventRow key={ev.id} event={ev} />
                        ))}
                    </ul>
                )}
            </section>
        </div>
    );
}
