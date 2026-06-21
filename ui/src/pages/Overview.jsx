import { useEffect, useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { LineChart, Line, ResponsiveContainer, YAxis } from 'recharts';
import { useStatus, useMetricsHistory } from '../ipc/hooks.js';

function StatusPill({ status }) {
    if (!status) return <span className="pill pill--muted">Loading…</span>;
    if (!status.registered) return <span className="pill pill--warn">Not paired</span>;
    if (status.connected) return <span className="pill pill--ok">Connected</span>;
    if (status.running) return <span className="pill pill--warn">Reconnecting</span>;
    return <span className="pill pill--muted">Stopped</span>;
}

function CopyButton({ value }) {
    const [copied, setCopied] = useState(false);
    if (!value) return null;
    return (
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
            {copied ? <Check size={14} /> : <Copy size={14} />}
        </button>
    );
}

function formatUptime(seconds) {
    if (!seconds || seconds < 0) return '—';
    const s = Math.floor(seconds);
    const days = Math.floor(s / 86400);
    const hours = Math.floor((s % 86400) / 3600);
    const minutes = Math.floor((s % 3600) / 60);
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m ${s % 60}s`;
    return `${s}s`;
}

function Sparkline({ data, dataKey, accent }) {
    if (!data || data.length === 0) {
        return <div className="sparkline sparkline--empty">collecting samples…</div>;
    }
    return (
        <div className="sparkline">
            <ResponsiveContainer width="100%" height={64}>
                <LineChart data={data} margin={{ top: 4, right: 4, bottom: 4, left: 4 }}>
                    <YAxis hide domain={[0, 100]} />
                    <Line
                        type="monotone"
                        dataKey={dataKey}
                        stroke={accent}
                        strokeWidth={2}
                        dot={false}
                        isAnimationActive={false}
                    />
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
}

export default function Overview() {
    const { status, error: statusError } = useStatus(2000);
    const { samples } = useMetricsHistory(2000);

    // Recharts wants plain objects; flatten the IPC payload.
    const chartData = samples.map((s) => ({
        t: s.t,
        cpu: s.cpu,
        mem: s.mem,
    }));

    const lastCpu = chartData.length ? chartData[chartData.length - 1].cpu : status?.cpu_percent;
    const lastMem = chartData.length ? chartData[chartData.length - 1].mem : status?.mem_percent;

    return (
        <div className="page">
            <header className="page__header">
                <div>
                    <h1 className="page__title">{status?.agent_name || 'Agent'}</h1>
                    <div className="page__sub">
                        <StatusPill status={status} />
                        {status?.version && <span className="muted">v{status.version}</span>}
                    </div>
                </div>
            </header>

            {statusError && (
                <div className="banner banner--warn">
                    Can't reach the agent IPC server. Is the service running? ({statusError})
                </div>
            )}

            <section className="card">
                <h2 className="card__title">Connection</h2>
                <div className="info-row">
                    <span className="info-row__label">Server URL</span>
                    <span className="info-row__value info-row__value--mono">
                        {status?.server_url || '—'}
                        <CopyButton value={status?.server_url} />
                    </span>
                </div>
                <div className="info-row">
                    <span className="info-row__label">Agent ID</span>
                    <span className="info-row__value info-row__value--mono">
                        {status?.agent_id || '—'}
                        <CopyButton value={status?.agent_id} />
                    </span>
                </div>
                <div className="info-row">
                    <span className="info-row__label">Transport</span>
                    <span className="info-row__value">
                        {status?.transport === 'poll' ? 'Polling (REST fallback)' : 'WebSocket'}
                    </span>
                </div>
                <div className="info-row">
                    <span className="info-row__label">Agent version</span>
                    <span className="info-row__value">{status?.version ? `v${status.version}` : '—'}</span>
                </div>
                <div className="info-row">
                    <span className="info-row__label">Uptime</span>
                    <span className="info-row__value">{formatUptime(status?.uptime_seconds)}</span>
                </div>
            </section>

            <section className="metrics">
                <div className="card metric-card">
                    <div className="metric-card__head">
                        <h2 className="card__title">CPU</h2>
                        <span className="metric-card__value">
                            {lastCpu != null ? `${lastCpu.toFixed(1)}%` : '—'}
                        </span>
                    </div>
                    <Sparkline data={chartData} dataKey="cpu" accent="#6366f1" />
                </div>
                <div className="card metric-card">
                    <div className="metric-card__head">
                        <h2 className="card__title">Memory</h2>
                        <span className="metric-card__value">
                            {lastMem != null ? `${lastMem.toFixed(1)}%` : '—'}
                        </span>
                    </div>
                    <Sparkline data={chartData} dataKey="mem" accent="#10b981" />
                </div>
            </section>
        </div>
    );
}
