import { useEffect, useState } from 'react';
import { Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom';
import Shell from './components/Shell.jsx';
import Overview from './pages/Overview.jsx';
import Activity from './pages/Activity.jsx';
import Logs from './pages/Logs.jsx';
import Actions from './pages/Actions.jsx';
import About from './pages/About.jsx';
import Pair from './pages/Pair.jsx';
import { local } from './ipc/client.js';

// PairGate uses /local/status (authoritative — reads config.yaml in this
// process) as the single source of truth for registration. Earlier
// versions also consulted the agent service IPC, but that endpoint is
// silent on a fresh install (the service won't even start without a
// config), which let users wander into Overview / Actions before pairing
// — exactly the "let me click around an unconfigured app" report.
//
// We deliberately render NOTHING until the first /local/status resolves.
// The HTML splash from index.html stays on screen during that window, so
// the user sees a loading state instead of partial UI.
function PairGate({ children }) {
    const [registered, setRegistered] = useState(null); // null=unknown
    const location = useLocation();
    const navigate = useNavigate();

    useEffect(() => {
        let cancelled = false;
        async function tick() {
            try {
                const s = await local.status();
                if (!cancelled) setRegistered(Boolean(s && s.registered));
            } catch {
                // Same-process call — if this fails the asset server is
                // gone and the window is closing.
            }
        }
        tick();
        const id = setInterval(tick, 2000);
        return () => { cancelled = true; clearInterval(id); };
    }, []);

    useEffect(() => {
        if (registered === null) return; // wait for first answer
        const onPair = location.pathname === '/pair';
        if (!registered && !onPair) {
            navigate('/pair', { replace: true });
        }
    }, [registered, location.pathname, navigate]);

    // Hold render until we know — prevents the unpaired user from seeing
    // Overview / Actions for a beat before being kicked to /pair.
    if (registered === null) return null;

    // Hard-deny the non-pair routes when unregistered. The navigate() in
    // the effect handles the redirect; this keeps the children blank in
    // the same render so we don't flash the wrong page.
    if (!registered && location.pathname !== '/pair') return null;

    return children;
}

export default function App() {
    return (
        <PairGate>
            <Routes>
                <Route path="/pair" element={<Pair />} />
                <Route element={<Shell />}>
                    <Route path="/overview" element={<Overview />} />
                    <Route path="/activity" element={<Activity />} />
                    <Route path="/logs" element={<Logs />} />
                    <Route path="/actions" element={<Actions />} />
                    <Route path="/about" element={<About />} />
                </Route>
                <Route path="*" element={<Navigate to="/overview" replace />} />
            </Routes>
        </PairGate>
    );
}
