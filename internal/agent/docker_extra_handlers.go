package agent

// Phase 1e — fill in the docker actions that were declared in the
// protocol but never wired to handlers: container:create,
// container:exec, image:build, volume:create, network:create. The
// existing handlers (start/stop/list/inspect/logs/stats, image
// list/pull/remove, compose) live in agent.go alongside their
// containers; we put the new ones in their own file to keep the diff
// reviewable.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/docker"
	"github.com/jhd3197/serverkit-agent/internal/jobs"
)

// validateImageName rejects shell metacharacters in user-supplied image
// references. Docker is generally tolerant about what it accepts as a
// tag, but we don't want a "registry.example.com/img;rm -rf /" landing
// in argv even if exec.Command is safe — it's a clearer error to
// reject up front.
func validateImageName(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("image is required")
	}
	if strings.ContainsAny(s, ";&|`$<>\n\r\"'\\") {
		return fmt.Errorf("invalid image: %q", s)
	}
	return nil
}

func validateContainerID(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("container is required")
	}
	if strings.ContainsAny(s, ";&|`$<>\n\r\"'\\ /") {
		return fmt.Errorf("invalid container id/name: %q", s)
	}
	return nil
}

// ───── docker:container:create ────────────────────────────────────

func (a *Agent) handleDockerContainerCreate(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if a.docker == nil {
		return nil, errors.New("docker not available")
	}
	var spec docker.ContainerCreateSpec
	if err := json.Unmarshal(params, &spec); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := validateImageName(spec.Image); err != nil {
		return nil, err
	}
	// v1 reject privileged-ish fields. They round-trip in the JSON but
	// are not part of ContainerCreateSpec — defensively check raw params
	// to fail loudly when a caller tries to set them. The struct-shaped
	// check is at the field level above.
	var raw map[string]interface{}
	_ = json.Unmarshal(params, &raw)
	for _, banned := range []string{"privileged", "cap_add", "devices"} {
		if _, ok := raw[banned]; ok {
			return nil, fmt.Errorf("%s is not supported in v1 container:create", banned)
		}
	}
	id, err := a.docker.CreateContainer(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}
	return map[string]interface{}{
		"id":     id,
		"name":   spec.Name,
		"image":  spec.Image,
		"status": "created",
	}, nil
}

// ───── docker:container:exec ──────────────────────────────────────

func (a *Agent) handleDockerContainerExec(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if a.docker == nil {
		return nil, errors.New("docker not available")
	}
	var p struct {
		Container      string   `json:"container"`
		Cmd            []string `json:"cmd"`
		User           string   `json:"user"`
		WorkingDir     string   `json:"working_dir"`
		TimeoutSeconds int      `json:"timeout_seconds"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := validateContainerID(p.Container); err != nil {
		return nil, err
	}
	if len(p.Cmd) == 0 {
		return nil, errors.New("cmd is required")
	}
	timeout := time.Duration(p.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > 5*time.Minute {
		timeout = 60 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := a.docker.ExecContainer(cctx, p.Container, p.Cmd, p.User, p.WorkingDir, 1024*1024)
	if err != nil {
		return nil, fmt.Errorf("exec: %w", err)
	}
	return res, nil
}

// ───── docker:image:build ─────────────────────────────────────────

func (a *Agent) handleDockerImageBuild(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if a.docker == nil {
		return nil, errors.New("docker not available")
	}
	var spec docker.ImageBuildSpec
	if err := json.Unmarshal(params, &spec); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := validateImageName(spec.Tag); err != nil {
		return nil, fmt.Errorf("tag: %w", err)
	}
	abs, err := filepath.Abs(spec.ContextPath)
	if err != nil {
		return nil, fmt.Errorf("context_path: %w", err)
	}
	if !a.contextPathAllowed(abs) {
		return nil, fmt.Errorf("context_path %q is not under any allowed root", abs)
	}
	spec.ContextPath = abs

	job := a.jobs.New(500)
	go a.runDockerBuildJob(job, spec)
	return map[string]interface{}{
		"job_id":  job.ID,
		"channel": job.Channel,
		"tag":     spec.Tag,
	}, nil
}

func (a *Agent) contextPathAllowed(path string) bool {
	for _, root := range a.cfg.Security.AllowedPaths {
		ar, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		// path must be under ar (or equal). Use Rel to detect ".." escapes.
		rel, err := filepath.Rel(ar, path)
		if err != nil {
			continue
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (a *Agent) runDockerBuildJob(job *jobs.Job, spec docker.ImageBuildSpec) {
	exit := 0
	emitDone := func(errStr string) {
		_ = job.Push(a.ws, jobs.Event{
			Phase:    jobs.PhaseDone,
			ExitCode: &exit,
			Error:    errStr,
			Extra:    map[string]interface{}{"tag": spec.Tag},
		})
	}
	cctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	cmd, err := a.docker.BuildImageCmd(cctx, spec)
	if err != nil {
		exit = -1
		emitDone(err.Error())
		return
	}
	_ = job.Push(a.ws, jobs.Event{Phase: jobs.PhaseStart, Message: fmt.Sprintf("docker build -t %s", spec.Tag)})
	if err := streamCmdOutput(cmd, job, a.ws); err != nil {
		exit = -1
		emitDone(err.Error())
		return
	}
	if cerr := cmd.Wait(); cerr != nil {
		exit = exitCodeOfCmd(cerr)
		if exit == 0 {
			exit = -1
		}
		emitDone(cerr.Error())
		return
	}
	emitDone("")
}

// exitCodeOfCmd duplicates exitCodeOf from package_handlers.go to
// avoid an import cycle in this file. They're trivial enough that the
// duplication is cheaper than refactoring callers.
func exitCodeOfCmd(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// ───── docker:volume:create ───────────────────────────────────────

func (a *Agent) handleDockerVolumeCreate(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if a.docker == nil {
		return nil, errors.New("docker not available")
	}
	var p struct {
		Name   string            `json:"name"`
		Driver string            `json:"driver"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if strings.TrimSpace(p.Name) == "" {
		return nil, errors.New("name is required")
	}
	if strings.ContainsAny(p.Name, ";&|`$<>\n\r\"'\\ /") {
		return nil, fmt.Errorf("invalid volume name: %q", p.Name)
	}
	vol, err := a.docker.CreateVolume(ctx, p.Name, p.Driver, p.Labels)
	if err != nil {
		return nil, fmt.Errorf("create volume: %w", err)
	}
	return vol, nil
}

// ───── docker:network:create ──────────────────────────────────────

func (a *Agent) handleDockerNetworkCreate(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if a.docker == nil {
		return nil, errors.New("docker not available")
	}
	var spec docker.NetworkCreateSpec
	if err := json.Unmarshal(params, &spec); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if strings.TrimSpace(spec.Name) == "" {
		return nil, errors.New("name is required")
	}
	if strings.ContainsAny(spec.Name, ";&|`$<>\n\r\"'\\ /") {
		return nil, fmt.Errorf("invalid network name: %q", spec.Name)
	}
	id, err := a.docker.CreateNetwork(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("create network: %w", err)
	}
	return map[string]interface{}{
		"id":     id,
		"name":   spec.Name,
		"driver": spec.Driver,
	}, nil
}
