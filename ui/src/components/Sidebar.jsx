import { NavLink } from 'react-router-dom';
import {
    LayoutDashboard,
    History,
    FileText,
    Wrench,
    Info,
    Server,
} from 'lucide-react';
import { useStatus } from '../ipc/hooks.js';

const NAV = [
    { to: '/overview', label: 'Overview', icon: LayoutDashboard },
    { to: '/activity', label: 'Activity', icon: History },
    { to: '/logs', label: 'Logs', icon: FileText },
    { to: '/actions', label: 'Actions', icon: Wrench },
    { to: '/about', label: 'About', icon: Info },
];

export default function Sidebar() {
    // Pulled lazily — sidebar renders on every page so this hook is a
    // single shared subscription to /status. Errors are intentionally
    // ignored; the sidebar shows '—' when the version isn't known yet
    // rather than an error spinner.
    const { status } = useStatus(5000);
    return (
        <aside className="sidebar">
            <div className="sidebar__brand">
                <div className="sidebar__brand-icon">
                    <Server size={18} />
                </div>
                <div>
                    <div className="sidebar__brand-name">ServerKit</div>
                    <div className="sidebar__brand-sub">Agent Console</div>
                </div>
            </div>
            <nav className="sidebar__nav">
                {NAV.map(({ to, label, icon: Icon }) => (
                    <NavLink
                        key={to}
                        to={to}
                        className={({ isActive }) =>
                            'sidebar__link' + (isActive ? ' sidebar__link--active' : '')
                        }
                    >
                        <Icon size={16} />
                        <span>{label}</span>
                    </NavLink>
                ))}
            </nav>
            <div className="sidebar__footer">
                <div className="sidebar__version">v{status?.version || '—'}</div>
                {status?.transport === 'poll' && (
                    <div className="sidebar__transport" title="Connected via REST polling fallback">
                        polling
                    </div>
                )}
            </div>
        </aside>
    );
}
