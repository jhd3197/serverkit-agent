import { useEffect, useState, useRef } from 'react';
import { ipc } from './client.js';

// Generic polling hook. Calls fetcher() on mount and then every intervalMs.
// Cancels on unmount and treats overlapping requests defensively (last write
// wins, but a stale response can't overwrite the current one).
function usePolling(fetcher, intervalMs) {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const seq = useRef(0);

    useEffect(() => {
        let cancelled = false;
        async function tick() {
            const mySeq = ++seq.current;
            try {
                const result = await fetcher();
                if (cancelled || mySeq !== seq.current) return;
                setData(result);
                setError(null);
            } catch (err) {
                if (cancelled || mySeq !== seq.current) return;
                setError(err.message || String(err));
            }
        }
        tick();
        const id = setInterval(tick, intervalMs);
        return () => {
            cancelled = true;
            clearInterval(id);
        };
    // fetcher is captured by reference; in our use it's always a stable
    // module-level function, so we deliberately exclude it from deps.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [intervalMs]);

    return { data, error };
}

export function useStatus(intervalMs = 2000) {
    const { data, error } = usePolling(ipc.status, intervalMs);
    return { status: data, error };
}

export function useMetricsHistory(intervalMs = 2000) {
    const { data, error } = usePolling(ipc.metricsHistory, intervalMs);
    return { samples: data?.samples || [], error };
}

export function useConnection(intervalMs = 5000) {
    const { data, error } = usePolling(ipc.connection, intervalMs);
    return { connection: data, error };
}

export function useEvents(intervalMs = 3000) {
    const { data, error } = usePolling(() => ipc.events(0), intervalMs);
    return { events: data?.events || [], error };
}

export function useLogs(lines = 500, intervalMs = 2000) {
    const { data, error } = usePolling(() => ipc.logs(lines), intervalMs);
    return { lines: data?.lines || [], count: data?.count || 0, error };
}
