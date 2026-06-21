package agent

// Phase 1c additions — package manager actions beyond the original
// install/remove/list trio: search, info, update-cache, plus a
// streaming variant of install/upgrade that emits progress on a job
// channel for the Packages tab and one-click templates.
//
// The existing handlePackagesInstall (single-name, synchronous,
// idempotent short-circuit) is left alone so the workflow engine's
// agent_command callers still get a structured result. New callers
// wanting progress streaming use packages:install_async / packages:upgrade.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/jobs"
)

// extendedPackageManager carries the new-action arg patterns alongside
// the existing packageManager. We don't fold these into packageManager
// itself to keep the original definition (and its callers) untouched.
type extendedPackageManager struct {
	bin         string
	updateCache []string
	upgradeAll  []string
	upgradePkg  []string // appended with package name(s)
	searchCmd   []string
	infoCmd     []string // appended with name
}

func extendedFor(pm *packageManager) *extendedPackageManager {
	switch pm.bin {
	case "apt-get":
		return &extendedPackageManager{
			bin:         "apt-get",
			updateCache: []string{"update"},
			upgradeAll:  []string{"upgrade", "-y", "-o", "Dpkg::Options::=--force-confold"},
			upgradePkg:  []string{"install", "--only-upgrade", "-y", "-o", "Dpkg::Options::=--force-confold"},
			searchCmd:   []string{"search"}, // run via apt-cache below
			infoCmd:     []string{"show"},   // run via apt-cache below
		}
	case "dnf", "yum":
		return &extendedPackageManager{
			bin:         pm.bin,
			updateCache: []string{"check-update"},
			upgradeAll:  []string{"upgrade", "-y"},
			upgradePkg:  []string{"upgrade", "-y"},
			searchCmd:   []string{"search"},
			infoCmd:     []string{"info"},
		}
	case "apk":
		return &extendedPackageManager{
			bin:         "apk",
			updateCache: []string{"update"},
			upgradeAll:  []string{"upgrade"},
			upgradePkg:  []string{"upgrade"},
			searchCmd:   []string{"search", "-v"},
			infoCmd:     []string{"info"},
		}
	case "pacman":
		return &extendedPackageManager{
			bin:         "pacman",
			updateCache: []string{"-Sy"},
			upgradeAll:  []string{"-Syu", "--noconfirm"},
			upgradePkg:  []string{"-S", "--noconfirm"},
			searchCmd:   []string{"-Ss"},
			infoCmd:     []string{"-Si"},
		}
	case "zypper":
		return &extendedPackageManager{
			bin:         "zypper",
			updateCache: []string{"refresh"},
			upgradeAll:  []string{"update", "-y"},
			upgradePkg:  []string{"update", "-y"},
			searchCmd:   []string{"se"},
			infoCmd:     []string{"info"},
		}
	}
	return nil
}

// ───── packages:update_cache ──────────────────────────────────────

func (a *Agent) handlePackagesUpdateCache(ctx context.Context, params json.RawMessage) (interface{}, error) {
	pm, err := detectPackageManager()
	if err != nil {
		return nil, err
	}
	ext := extendedFor(pm)
	if ext == nil {
		return nil, fmt.Errorf("update_cache: manager %q not supported", pm.bin)
	}
	a.pkgLock.Lock()
	defer a.pkgLock.Unlock()

	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd, err := sudoCommandContext(cctx, a.sudoMode, ext.bin, ext.updateCache...)
	if err != nil {
		return nil, err
	}
	out, err := cmd.CombinedOutput()
	tail := truncate(string(out), 4096)
	if err != nil && !isCheckUpdateExit100(ext.bin, err) {
		// dnf check-update returns 100 when updates are available; that
		// isn't a failure, just an "actionable" exit. Anything else is
		// treated as a real error.
		if classifySudoError(string(out)) {
			return nil, fmt.Errorf("sudo refused: %w", errSudoRequired)
		}
		return nil, fmt.Errorf("%s %s: %w (%s)", ext.bin, strings.Join(ext.updateCache, " "), err, tail)
	}
	return map[string]interface{}{
		"manager": ext.bin,
		"output":  tail,
	}, nil
}

// dnf check-update conventionally exits 100 when there are updates
// pending, 0 when nothing to do. We treat both as success.
func isCheckUpdateExit100(bin string, err error) bool {
	if bin != "dnf" && bin != "yum" {
		return false
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode() == 100
	}
	return false
}

// ───── packages:search ────────────────────────────────────────────

func (a *Agent) handlePackagesSearch(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	q := strings.TrimSpace(p.Query)
	if q == "" {
		return nil, errors.New("query is required")
	}
	if err := validatePackageName(q); err != nil {
		// Reject metachars; reuse the install validator since search
		// goes straight to argv.
		return nil, err
	}
	if p.Limit <= 0 || p.Limit > 500 {
		p.Limit = 500
	}

	pm, err := detectPackageManager()
	if err != nil {
		return nil, err
	}
	ext := extendedFor(pm)
	if ext == nil {
		return nil, fmt.Errorf("search: manager %q not supported", pm.bin)
	}

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	bin := ext.bin
	args := append([]string{}, ext.searchCmd...)
	if pm.bin == "apt-get" {
		bin = "apt-cache"
	}
	args = append(args, q)
	out, err := exec.CommandContext(cctx, bin, args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), err)
	}
	lines := splitNonEmptyLines(string(out))
	if len(lines) > p.Limit {
		lines = lines[:p.Limit]
	}
	return map[string]interface{}{
		"manager": pm.bin,
		"query":   q,
		"limit":   p.Limit,
		"results": lines,
	}, nil
}

// ───── packages:info ──────────────────────────────────────────────

func (a *Agent) handlePackagesInfo(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := validatePackageName(p.Name); err != nil {
		return nil, err
	}
	pm, err := detectPackageManager()
	if err != nil {
		return nil, err
	}
	ext := extendedFor(pm)
	if ext == nil {
		return nil, fmt.Errorf("info: manager %q not supported", pm.bin)
	}

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	bin := ext.bin
	if pm.bin == "apt-get" {
		bin = "apt-cache"
	}
	args := append(append([]string{}, ext.infoCmd...), p.Name)
	out, err := exec.CommandContext(cctx, bin, args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), err)
	}
	return map[string]interface{}{
		"manager": pm.bin,
		"name":    p.Name,
		"output":  truncate(string(out), 16*1024),
	}, nil
}

// ───── packages:install_async + packages:upgrade ─────────────────

// installRequest is the shared param shape for install_async / upgrade.
// Either Names (list) or Name (single) may be set; an empty Names with
// All=true upgrades everything (only meaningful for upgrade).
type installRequest struct {
	Names []string `json:"names"`
	Name  string   `json:"name"`
	All   bool     `json:"all"`
}

func (r *installRequest) normalize() error {
	if r.Name != "" {
		r.Names = append(r.Names, r.Name)
	}
	for _, n := range r.Names {
		if err := validatePackageName(n); err != nil {
			return err
		}
	}
	return nil
}

// handlePackagesInstallAsync is a streaming variant of install: returns
// {job_id, channel} immediately and emits per-line progress on the
// channel. Idempotent like the sync variant — packages already
// installed are skipped (we still emit a status event).
func (a *Agent) handlePackagesInstallAsync(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p installRequest
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := p.normalize(); err != nil {
		return nil, err
	}
	if len(p.Names) == 0 {
		return nil, errors.New("at least one package name required")
	}
	pm, err := detectPackageManager()
	if err != nil {
		return nil, err
	}
	if a.sudoMode == SudoUnavailable {
		return nil, errSudoRequired
	}

	job := a.jobs.New(200)
	go a.runPackageInstallJob(job, pm, p.Names)
	return map[string]interface{}{
		"job_id":  job.ID,
		"channel": job.Channel,
	}, nil
}

// handlePackagesUpgrade upgrades the named packages, or all packages
// when All=true. Streams progress identically to install_async.
func (a *Agent) handlePackagesUpgrade(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p installRequest
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := p.normalize(); err != nil {
		return nil, err
	}
	if !p.All && len(p.Names) == 0 {
		return nil, errors.New("either names[] or all=true required")
	}
	pm, err := detectPackageManager()
	if err != nil {
		return nil, err
	}
	ext := extendedFor(pm)
	if ext == nil {
		return nil, fmt.Errorf("upgrade: manager %q not supported", pm.bin)
	}
	if a.sudoMode == SudoUnavailable {
		return nil, errSudoRequired
	}

	job := a.jobs.New(200)
	go a.runPackageUpgradeJob(job, pm, ext, p.Names, p.All)
	return map[string]interface{}{
		"job_id":  job.ID,
		"channel": job.Channel,
	}, nil
}

// runPackageInstallJob runs the apt/dnf/etc. install in the background,
// streams output line-by-line on the job channel, and emits a final
// done event with the structured result.
func (a *Agent) runPackageInstallJob(job *jobs.Job, pm *packageManager, names []string) {
	a.pkgLock.Lock()
	defer a.pkgLock.Unlock()

	exit := 0
	emitDone := func(errStr string, installed []string) {
		ev := jobs.Event{
			Phase:    jobs.PhaseDone,
			ExitCode: &exit,
			Error:    errStr,
			Extra: map[string]interface{}{
				"manager":   pm.bin,
				"action":    "install",
				"installed": installed,
			},
		}
		_ = job.Push(a.ws, ev)
	}

	// Skip already-installed packages.
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 30*time.Second)
	var toInstall, alreadyInstalled []string
	for _, n := range names {
		if installed, _ := pm.isInstalled(probeCtx, n); installed {
			alreadyInstalled = append(alreadyInstalled, n)
			continue
		}
		toInstall = append(toInstall, n)
	}
	probeCancel()

	if len(alreadyInstalled) > 0 {
		_ = job.Push(a.ws, jobs.Event{
			Phase:   jobs.PhaseStatus,
			Message: fmt.Sprintf("already installed: %s", strings.Join(alreadyInstalled, ", ")),
		})
	}
	if len(toInstall) == 0 {
		emitDone("", alreadyInstalled)
		return
	}

	_ = job.Push(a.ws, jobs.Event{
		Phase:   jobs.PhaseStart,
		Message: fmt.Sprintf("installing %d package(s) via %s", len(toInstall), pm.bin),
	})

	// Long-running command — bound at 15 minutes.
	cctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	args := append(append([]string{}, pm.install...), toInstall...)
	cmd, err := sudoCommandContext(cctx, a.sudoMode, pm.bin, args...)
	if err != nil {
		exit = -1
		emitDone(err.Error(), nil)
		return
	}
	if err := streamCmdOutput(cmd, job, a.ws); err != nil {
		exit = -1
		emitDone(err.Error(), nil)
		return
	}
	if cerr := cmd.Wait(); cerr != nil {
		exit = exitCodeOf(cerr)
		if exit == 0 {
			exit = -1
		}
		emitDone(cerr.Error(), nil)
		return
	}
	emitDone("", append(alreadyInstalled, toInstall...))
}

func (a *Agent) runPackageUpgradeJob(job *jobs.Job, pm *packageManager, ext *extendedPackageManager, names []string, all bool) {
	a.pkgLock.Lock()
	defer a.pkgLock.Unlock()

	exit := 0
	emitDone := func(errStr string) {
		ev := jobs.Event{
			Phase:    jobs.PhaseDone,
			ExitCode: &exit,
			Error:    errStr,
			Extra: map[string]interface{}{
				"manager": pm.bin,
				"action":  "upgrade",
				"all":     all,
			},
		}
		_ = job.Push(a.ws, ev)
	}

	cctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// apt: refresh the package index first so upgrade sees newly
	// published versions. Other managers do this implicitly.
	if pm.bin == "apt-get" {
		updCmd, err := sudoCommandContext(cctx, a.sudoMode, ext.bin, ext.updateCache...)
		if err != nil {
			exit = -1
			emitDone(err.Error())
			return
		}
		if err := streamCmdOutput(updCmd, job, a.ws); err != nil {
			exit = -1
			emitDone(err.Error())
			return
		}
		_ = updCmd.Wait()
	}

	var args []string
	if all {
		args = append([]string{}, ext.upgradeAll...)
	} else {
		args = append(append([]string{}, ext.upgradePkg...), names...)
	}
	cmd, err := sudoCommandContext(cctx, a.sudoMode, ext.bin, args...)
	if err != nil {
		exit = -1
		emitDone(err.Error())
		return
	}
	_ = job.Push(a.ws, jobs.Event{
		Phase:   jobs.PhaseStart,
		Message: fmt.Sprintf("%s %s", ext.bin, strings.Join(args, " ")),
	})
	if err := streamCmdOutput(cmd, job, a.ws); err != nil {
		exit = -1
		emitDone(err.Error())
		return
	}
	if cerr := cmd.Wait(); cerr != nil {
		exit = exitCodeOf(cerr)
		if exit == 0 {
			exit = -1
		}
		emitDone(cerr.Error())
		return
	}
	emitDone("")
}

// streamCmdOutput attaches a line-buffered stdout/stderr scanner to cmd
// and pushes batches of lines on the job channel. Lines are flushed on
// a 100ms window or 32-line threshold, whichever comes first, so the
// panel sees steady progress without one event per line at high
// throughput.
//
// Blocks until both pipes close, then returns. Caller is expected to
// invoke cmd.Wait() afterwards to reap the process and get the exit
// code. Returns an error only if cmd.Start fails or pipe setup fails.
func streamCmdOutput(cmd *exec.Cmd, job *jobs.Job, s jobs.Streamer) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	lines := make(chan string, 256)
	var wg sync.WaitGroup
	wg.Add(2)
	go scanLines(stdout, lines, &wg)
	go scanLines(stderr, lines, &wg)

	// Closer goroutine: once both scanners have returned, close the
	// channel so the batcher knows there's no more input.
	go func() {
		wg.Wait()
		close(lines)
	}()

	// Batcher: flush every 100ms or 32 lines. Runs synchronously so
	// the caller can rely on "all output emitted before we return."
	batch := make([]string, 0, 32)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		_ = job.Push(s, jobs.Event{Phase: jobs.PhaseLog, Lines: append([]string{}, batch...)})
		batch = batch[:0]
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case ln, ok := <-lines:
			if !ok {
				flush()
				return nil
			}
			batch = append(batch, ln)
			if len(batch) >= 32 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func scanLines(r io.ReadCloser, out chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	defer r.Close()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		out <- sc.Text()
	}
}

func exitCodeOf(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func splitNonEmptyLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if strings.TrimSpace(ln) == "" {
			continue
		}
		out = append(out, ln)
	}
	return out
}

