import { useEffect, useMemo, useRef, useState } from 'react';
import { Trash2, Search } from 'lucide-react';
import { useLogs } from '../ipc/hooks.js';
import { ipc } from '../ipc/client.js';

const LEVELS = ['all', 'info', 'warn', 'error'];

// Each line is one JSON object emitted by slog. Tolerate plain text too —
// during early boot the lumberjack rotation can produce a mixed file.
function parseLine(raw) {
    try {
        const obj = JSON.parse(raw);
        return {
            time: obj.time || '',
            level: (obj.level || 'INFO').toLowerCase(),
            msg: obj.msg || '',
            component: obj.component || '',
            extras: extractExtras(obj),
            raw,
        };
    } catch {
        return { time: '', level: 'info', msg: raw, component: '', extras: {}, raw };
    }
}

function extractExtras(obj) {
    const skip = new Set(['time', 'level', 'msg', 'component']);
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
        if (!skip.has(k)) out[k] = v;
    }
    return out;
}

function formatTime(iso) {
    if (!iso) return '';
    // ISO strings are long; surface only HH:MM:SS plus milliseconds.
    const m = /T(\d{2}:\d{2}:\d{2}\.\d{3})/.exec(iso);
    return m ? m[1] : iso;
}

function LogRow({ entry }) {
    const lvl = entry.level || 'info';
    return (
        <div className={`logrow logrow--${lvl}`}>
            <span className="logrow__time">{formatTime(entry.time)}</span>
            <span className={`logrow__level logrow__level--${lvl}`}>{lvl}</span>
            {entry.component && <span className="logrow__component">{entry.component}</span>}
            <span className="logrow__msg">{entry.msg}</span>
            {Object.keys(entry.extras).length > 0 && (
                <span className="logrow__extras">
                    {Object.entries(entry.extras).map(([k, v]) => (
                        <span key={k}>
                            <em>{k}=</em>
                            <code>{typeof v === 'string' ? v : JSON.stringify(v)}</code>
                        </span>
                    ))}
                </span>
            )}
        </div>
    );
}

export default function Logs() {
    const { lines, error } = useLogs(500, 2000);
    const [filter, setFilter] = useState('all');
    const [query, setQuery] = useState('');
    const [autoScroll, setAutoScroll] = useState(true);
    const [clearing, setClearing] = useState(false);
    const scrollerRef = useRef(null);

    const parsed = useMemo(() => lines.map(parseLine), [lines]);

    const visible = useMemo(() => {
        const q = query.trim().toLowerCase();
        return parsed.filter((e) => {
            if (filter !== 'all' && e.level !== filter) return false;
            if (q && !e.raw.toLowerCase().includes(q)) return false;
            return true;
        });
    }, [parsed, filter, query]);

    // Auto-scroll on new lines unless the user has scrolled up. Conservative
    // heuristic: if the scroller is within 100 px of the bottom we treat the
    // user as "following" the tail.
    useEffect(() => {
        if (!autoScroll || !scrollerRef.current) return;
        const el = scrollerRef.current;
        el.scrollTop = el.scrollHeight;
    }, [visible.length, autoScroll]);

    function onScroll() {
        if (!scrollerRef.current) return;
        const el = scrollerRef.current;
        const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 100;
        setAutoScroll(atBottom);
    }

    async function handleClear() {
        if (clearing) return;
        setClearing(true);
        try {
            await ipc.clearLogs();
        } catch (err) {
            // Surface the failure on the auto-scroll banner area; full error
            // reporting comes when we add toast notifications later.
            console.error('clearLogs failed', err);
        } finally {
            setClearing(false);
        }
    }

    return (
        <div className="page page--full">
            <header className="page__header">
                <div>
                    <h1 className="page__title">Logs</h1>
                    <p className="page__sub muted">
                        Live tail of agent.log — last {lines.length} lines.
                    </p>
                </div>
                <div className="filter-group">
                    {LEVELS.map((l) => (
                        <button
                            key={l}
                            type="button"
                            className={'chip' + (filter === l ? ' chip--active' : '')}
                            onClick={() => setFilter(l)}
                        >
                            {l}
                        </button>
                    ))}
                </div>
            </header>

            <div className="toolbar">
                <div className="search">
                    <Search size={14} />
                    <input
                        type="text"
                        placeholder="Search…"
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        spellCheck={false}
                    />
                </div>
                <div className="toolbar__spacer" />
                <button
                    type="button"
                    className="btn btn--danger"
                    onClick={handleClear}
                    disabled={clearing}
                    title="Rotates agent.log to a backup file"
                >
                    <Trash2 size={14} />
                    {clearing ? 'Clearing…' : 'Clear'}
                </button>
            </div>

            {error && (
                <div className="banner banner--warn">
                    Can't reach the agent IPC server. ({error})
                </div>
            )}

            <div className="log-viewer" ref={scrollerRef} onScroll={onScroll}>
                {visible.length === 0 ? (
                    <div className="empty-state empty-state--log">
                        {lines.length === 0
                            ? 'Waiting for log lines…'
                            : `No matches for "${query}" / ${filter}`}
                    </div>
                ) : (
                    visible.map((entry, i) => <LogRow key={i} entry={entry} />)
                )}
            </div>

            {!autoScroll && (
                <div className="follow-pill" onClick={() => setAutoScroll(true)}>
                    Resume tail ↓
                </div>
            )}
        </div>
    );
}
