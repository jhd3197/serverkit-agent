import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The agent embeds the built dist directly into the Go binary via embed.FS,
// then serves it from a localhost HTTP server inside WebView2. Assets are
// referenced relatively so the served base URL doesn't matter.
export default defineConfig({
    plugins: [react()],
    base: './',
    server: {
        port: 5174,
        strictPort: true,
    },
    build: {
        // Output directly into the Go package that embeds it, so the only
        // build orchestration is "npm run build" then "go build" — no
        // separate copy step. The dir is gitignored; embed requires it to
        // exist at compile time, so the Makefile / docs make the order
        // explicit.
        outDir: '../internal/agentui/dist',
        emptyOutDir: true,
        chunkSizeWarningLimit: 800,
    },
});
