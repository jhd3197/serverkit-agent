package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/jhd3197/serverkit-agent/internal/config"
	"gopkg.in/natefinch/lumberjack.v2"
	"log/slog"
)

// resilientWriter wraps multiple io.Writers and writes to all of them
// independently, swallowing per-writer errors. The standard library's
// io.MultiWriter aborts the entire write chain on the first error,
// which is a real bug on Windows services: a single transient stdout
// write failure (closed handle, ERROR_NO_DATA, etc.) blocks the
// lumberjack file writer from ever getting subsequent log records.
// That's how agent.log ended up at 0 bytes while events.json worked
// fine — events.json uses a direct os.File handle, not slog's
// handler chain.
type resilientWriter struct {
	mu      sync.Mutex
	writers []io.Writer
}

func (r *resilientWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, w := range r.writers {
		// Best-effort: write to each writer, but never let one writer's
		// failure cascade to another. Returns len(p), nil unconditionally
		// so slog never sees a write error and disables itself.
		_, _ = w.Write(p)
	}
	return len(p), nil
}

// Logger wraps slog.Logger with additional context
type Logger struct {
	*slog.Logger
	// rotator is the lumberjack writer when file logging is enabled. Nil
	// when only stdout is configured. Exposed via Rotate() so the desktop
	// console's Logs-tab "Clear" button can roll the file without racing
	// the live writer.
	rotator *lumberjack.Logger
}

// New creates a new logger with the given configuration
func New(cfg config.LoggingConfig) *Logger {
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var writers []io.Writer
	// Capture init errors so we can write them somewhere visible after
	// the logger is constructed — silently swallowing them was how we
	// got 0-byte agent.log files in the first place.
	var initErrs []string

	// Always write to stdout (services on Windows: still safe even if
	// the write goes nowhere — resilientWriter swallows per-writer
	// errors).
	writers = append(writers, os.Stdout)

	// Also write to file if configured.
	var rotator *lumberjack.Logger
	if cfg.File != "" {
		dir := filepath.Dir(cfg.File)
		if err := os.MkdirAll(dir, 0755); err != nil {
			initErrs = append(initErrs, fmt.Sprintf("MkdirAll(%q): %v", dir, err))
		} else {
			// Probe file writability before handing the path to lumberjack
			// so a permission error gets surfaced at boot instead of
			// silently disabling file logging.
			if f, perr := os.OpenFile(cfg.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); perr != nil {
				initErrs = append(initErrs, fmt.Sprintf("OpenFile(%q): %v", cfg.File, perr))
			} else {
				_ = f.Close()
				rotator = &lumberjack.Logger{
					Filename:   cfg.File,
					MaxSize:    cfg.MaxSize, // megabytes
					MaxBackups: cfg.MaxBackups,
					MaxAge:     cfg.MaxAge, // days
					Compress:   cfg.Compress,
				}
				writers = append(writers, rotator)
			}
		}
	}

	multi := &resilientWriter{writers: writers}
	handler := slog.NewJSONHandler(multi, opts)
	logger := slog.New(handler)

	// If rotator wired up successfully, drop a startup marker so the
	// file is never confused with "logger broken" — empty file is the
	// failure mode we just fixed, so always emit one explicit line.
	if rotator != nil {
		logger.Info("logger initialized",
			"file", cfg.File, "level", cfg.Level,
			"max_size_mb", cfg.MaxSize, "max_backups", cfg.MaxBackups)
	}
	for _, e := range initErrs {
		// Visible on stdout AND via slog (which still has rotator==nil
		// in this branch — best-effort visibility either way).
		logger.Warn("logger init issue", "error", e)
	}

	return &Logger{Logger: logger, rotator: rotator}
}

// Rotate triggers a manual log rotation. No-op when file logging is
// disabled. Used by the desktop console's "Clear logs" button so the live
// writer flushes to a backup before the in-memory tail clears.
func (l *Logger) Rotate() error {
	if l.rotator == nil {
		return nil
	}
	return l.rotator.Rotate()
}

// With returns a new logger with additional attributes. Carries the rotator
// reference so component loggers can also trigger rotation if needed.
func (l *Logger) With(args ...any) *Logger {
	return &Logger{Logger: l.Logger.With(args...), rotator: l.rotator}
}

// WithComponent returns a logger with a component name
func (l *Logger) WithComponent(name string) *Logger {
	return l.With("component", name)
}
