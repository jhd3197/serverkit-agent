package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	networktypes "github.com/docker/docker/api/types/network"
	volumetypes "github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/logger"
)

// Client wraps the Docker client with additional functionality
type Client struct {
	cli *client.Client
	cfg config.DockerConfig
	log *logger.Logger
}

// ContainerInfo represents container information
type ContainerInfo struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	ImageID string            `json:"image_id"`
	Command string            `json:"command"`
	Created int64             `json:"created"`
	State   string            `json:"state"`
	Status  string            `json:"status"`
	Ports   []PortMapping     `json:"ports"`
	Labels  map[string]string `json:"labels"`
}

// PortMapping represents a port mapping
type PortMapping struct {
	IP          string `json:"ip,omitempty"`
	PrivatePort uint16 `json:"private_port"`
	PublicPort  uint16 `json:"public_port,omitempty"`
	Type        string `json:"type"`
}

// ContainerStats represents container statistics
type ContainerStats struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryUsage   uint64  `json:"memory_usage"`
	MemoryLimit   uint64  `json:"memory_limit"`
	MemoryPercent float64 `json:"memory_percent"`
	NetworkRx     uint64  `json:"network_rx"`
	NetworkTx     uint64  `json:"network_tx"`
	BlockRead     uint64  `json:"block_read"`
	BlockWrite    uint64  `json:"block_write"`
	PIDs          uint64  `json:"pids"`
}

// ImageInfo represents image information
type ImageInfo struct {
	ID          string   `json:"id"`
	RepoTags    []string `json:"repo_tags"`
	RepoDigests []string `json:"repo_digests"`
	Created     int64    `json:"created"`
	Size        int64    `json:"size"`
}

// VolumeInfo represents volume information
type VolumeInfo struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint"`
	Labels     map[string]string `json:"labels"`
	Scope      string            `json:"scope"`
	CreatedAt  string            `json:"created_at"`
}

// NetworkInfo represents network information
type NetworkInfo struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Scope      string            `json:"scope"`
	Internal   bool              `json:"internal"`
	Labels     map[string]string `json:"labels"`
	Containers int               `json:"containers"`
}

// NewClient creates a new Docker client
func NewClient(cfg config.DockerConfig, log *logger.Logger) (*Client, error) {
	var opts []client.Opt

	// Set host if configured
	if cfg.Socket != "" {
		host := cfg.Socket
		// Convert socket path to Docker format
		if strings.HasPrefix(host, "/") {
			host = "unix://" + host
		}
		opts = append(opts, client.WithHost(host))
	}

	opts = append(opts, client.WithAPIVersionNegotiation())

	if cfg.Timeout > 0 {
		opts = append(opts, client.WithTimeout(cfg.Timeout))
	}

	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	return &Client{
		cli: cli,
		cfg: cfg,
		log: log.WithComponent("docker"),
	}, nil
}

// Ping checks if Docker is available
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.cli.Ping(ctx)
	return err
}

// Version returns the Docker version
func (c *Client) Version(ctx context.Context) (string, error) {
	info, err := c.cli.ServerVersion(ctx)
	if err != nil {
		return "", err
	}
	return info.Version, nil
}

// Info returns Docker system info
func (c *Client) Info(ctx context.Context) (*types.Info, error) {
	info, err := c.cli.Info(ctx)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// ListContainers lists all containers
func (c *Client) ListContainers(ctx context.Context, all bool) ([]ContainerInfo, error) {
	containers, err := c.cli.ContainerList(ctx, types.ContainerListOptions{
		All: all,
	})
	if err != nil {
		return nil, err
	}

	result := make([]ContainerInfo, len(containers))
	for i, cont := range containers {
		ports := make([]PortMapping, len(cont.Ports))
		for j, p := range cont.Ports {
			ports[j] = PortMapping{
				IP:          p.IP,
				PrivatePort: p.PrivatePort,
				PublicPort:  p.PublicPort,
				Type:        p.Type,
			}
		}

		name := ""
		if len(cont.Names) > 0 {
			name = strings.TrimPrefix(cont.Names[0], "/")
		}

		result[i] = ContainerInfo{
			ID:      cont.ID[:12],
			Name:    name,
			Image:   cont.Image,
			ImageID: cont.ImageID,
			Command: cont.Command,
			Created: cont.Created,
			State:   cont.State,
			Status:  cont.Status,
			Ports:   ports,
			Labels:  cont.Labels,
		}
	}

	return result, nil
}

// InspectContainer inspects a container
func (c *Client) InspectContainer(ctx context.Context, id string) (*types.ContainerJSON, error) {
	cont, err := c.cli.ContainerInspect(ctx, id)
	if err != nil {
		return nil, err
	}
	return &cont, nil
}

// StartContainer starts a container
func (c *Client) StartContainer(ctx context.Context, id string) error {
	return c.cli.ContainerStart(ctx, id, types.ContainerStartOptions{})
}

// StopContainer stops a container
func (c *Client) StopContainer(ctx context.Context, id string, timeout *int) error {
	var stopOpts containertypes.StopOptions
	if timeout != nil {
		stopOpts.Timeout = timeout
	}
	return c.cli.ContainerStop(ctx, id, stopOpts)
}

// RestartContainer restarts a container
func (c *Client) RestartContainer(ctx context.Context, id string, timeout *int) error {
	var stopOpts containertypes.StopOptions
	if timeout != nil {
		stopOpts.Timeout = timeout
	}
	return c.cli.ContainerRestart(ctx, id, stopOpts)
}

// RemoveContainer removes a container
func (c *Client) RemoveContainer(ctx context.Context, id string, force, removeVolumes bool) error {
	return c.cli.ContainerRemove(ctx, id, types.ContainerRemoveOptions{
		Force:         force,
		RemoveVolumes: removeVolumes,
	})
}

// ContainerLogs returns container logs
func (c *Client) ContainerLogs(ctx context.Context, id string, tail string, since string, follow bool) (io.ReadCloser, error) {
	opts := types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     follow,
		Timestamps: true,
	}

	if tail != "" {
		opts.Tail = tail
	}

	if since != "" {
		opts.Since = since
	}

	return c.cli.ContainerLogs(ctx, id, opts)
}

// ContainerStats returns container stats
func (c *Client) ContainerStats(ctx context.Context, id string) (*ContainerStats, error) {
	resp, err := c.cli.ContainerStats(ctx, id, false)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var stats types.StatsJSON
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, err
	}

	// Calculate CPU percentage
	cpuPercent := calculateCPUPercent(&stats)

	// Calculate memory percentage
	memPercent := 0.0
	if stats.MemoryStats.Limit > 0 {
		memPercent = float64(stats.MemoryStats.Usage) / float64(stats.MemoryStats.Limit) * 100
	}

	// Calculate network I/O
	var rx, tx uint64
	for _, net := range stats.Networks {
		rx += net.RxBytes
		tx += net.TxBytes
	}

	// Calculate block I/O
	var read, write uint64
	for _, bio := range stats.BlkioStats.IoServiceBytesRecursive {
		if bio.Op == "Read" {
			read += bio.Value
		} else if bio.Op == "Write" {
			write += bio.Value
		}
	}

	// Get container name
	inspect, _ := c.cli.ContainerInspect(ctx, id)
	name := strings.TrimPrefix(inspect.Name, "/")

	return &ContainerStats{
		ID:            id[:12],
		Name:          name,
		CPUPercent:    cpuPercent,
		MemoryUsage:   stats.MemoryStats.Usage,
		MemoryLimit:   stats.MemoryStats.Limit,
		MemoryPercent: memPercent,
		NetworkRx:     rx,
		NetworkTx:     tx,
		BlockRead:     read,
		BlockWrite:    write,
		PIDs:          stats.PidsStats.Current,
	}, nil
}

// ListImages lists all images
func (c *Client) ListImages(ctx context.Context) ([]ImageInfo, error) {
	images, err := c.cli.ImageList(ctx, types.ImageListOptions{})
	if err != nil {
		return nil, err
	}

	result := make([]ImageInfo, len(images))
	for i, img := range images {
		result[i] = ImageInfo{
			ID:          img.ID,
			RepoTags:    img.RepoTags,
			RepoDigests: img.RepoDigests,
			Created:     img.Created,
			Size:        img.Size,
		}
	}

	return result, nil
}

// PullImage pulls an image
func (c *Client) PullImage(ctx context.Context, imageName string) (io.ReadCloser, error) {
	return c.cli.ImagePull(ctx, imageName, types.ImagePullOptions{})
}

// RemoveImage removes an image
func (c *Client) RemoveImage(ctx context.Context, id string, force bool) error {
	_, err := c.cli.ImageRemove(ctx, id, types.ImageRemoveOptions{
		Force: force,
	})
	return err
}

// ListVolumes lists all volumes
func (c *Client) ListVolumes(ctx context.Context) ([]VolumeInfo, error) {
	resp, err := c.cli.VolumeList(ctx, volumetypes.ListOptions{})
	if err != nil {
		return nil, err
	}

	result := make([]VolumeInfo, len(resp.Volumes))
	for i, vol := range resp.Volumes {
		result[i] = VolumeInfo{
			Name:       vol.Name,
			Driver:     vol.Driver,
			Mountpoint: vol.Mountpoint,
			Labels:     vol.Labels,
			Scope:      vol.Scope,
			CreatedAt:  vol.CreatedAt,
		}
	}

	return result, nil
}

// CreateVolume creates a volume
func (c *Client) CreateVolume(ctx context.Context, name, driver string, labels map[string]string) (*VolumeInfo, error) {
	vol, err := c.cli.VolumeCreate(ctx, volumetypes.CreateOptions{
		Name:   name,
		Driver: driver,
		Labels: labels,
	})
	if err != nil {
		return nil, err
	}

	return &VolumeInfo{
		Name:       vol.Name,
		Driver:     vol.Driver,
		Mountpoint: vol.Mountpoint,
		Labels:     vol.Labels,
		Scope:      vol.Scope,
		CreatedAt:  vol.CreatedAt,
	}, nil
}

// RemoveVolume removes a volume
func (c *Client) RemoveVolume(ctx context.Context, name string, force bool) error {
	return c.cli.VolumeRemove(ctx, name, force)
}

// ListNetworks lists all networks
func (c *Client) ListNetworks(ctx context.Context) ([]NetworkInfo, error) {
	networks, err := c.cli.NetworkList(ctx, types.NetworkListOptions{})
	if err != nil {
		return nil, err
	}

	result := make([]NetworkInfo, len(networks))
	for i, net := range networks {
		result[i] = NetworkInfo{
			ID:         net.ID[:12],
			Name:       net.Name,
			Driver:     net.Driver,
			Scope:      net.Scope,
			Internal:   net.Internal,
			Labels:     net.Labels,
			Containers: len(net.Containers),
		}
	}

	return result, nil
}

// RemoveNetwork removes a network
func (c *Client) RemoveNetwork(ctx context.Context, id string) error {
	return c.cli.NetworkRemove(ctx, id)
}

// GetContainerCount returns the number of containers
func (c *Client) GetContainerCount(ctx context.Context) (total int, running int, err error) {
	allContainers, err := c.cli.ContainerList(ctx, types.ContainerListOptions{All: true})
	if err != nil {
		return 0, 0, err
	}

	runningContainers, err := c.cli.ContainerList(ctx, types.ContainerListOptions{
		Filters: filters.NewArgs(filters.Arg("status", "running")),
	})
	if err != nil {
		return 0, 0, err
	}

	return len(allContainers), len(runningContainers), nil
}

// Close closes the Docker client
func (c *Client) Close() error {
	return c.cli.Close()
}

// ───── container:create / container:exec / image:build / network:create

// ContainerCreateSpec is the curated input shape for CreateContainer.
// We deliberately don't expose raw HostConfig — the panel sends the
// fields a one-click template needs and we map them. Privileged /
// CapAdd / Devices are intentionally absent in v1; if a user needs
// them they should run `docker create` directly.
type ContainerCreateSpec struct {
	Image         string            `json:"image"`
	Name          string            `json:"name,omitempty"`
	Command       []string          `json:"command,omitempty"`
	Env           []string          `json:"env,omitempty"` // KEY=VAL
	Labels        map[string]string `json:"labels,omitempty"`
	RestartPolicy string            `json:"restart_policy,omitempty"` // no, on-failure, always, unless-stopped
	Network       string            `json:"network,omitempty"`
	Ports         []ContainerPort   `json:"ports,omitempty"`
	Volumes       []ContainerMount  `json:"volumes,omitempty"`
	WorkingDir    string            `json:"working_dir,omitempty"`
}

type ContainerPort struct {
	Host      uint16 `json:"host"`
	Container uint16 `json:"container"`
	Proto     string `json:"proto,omitempty"` // "tcp" (default) or "udp"
}

type ContainerMount struct {
	Source string `json:"src"`
	Target string `json:"dst"`
	Mode   string `json:"mode,omitempty"` // "ro" or "" for rw
}

// CreateContainer wires a curated spec to the Docker SDK's
// ContainerCreate. Returns the new container ID.
func (c *Client) CreateContainer(ctx context.Context, spec ContainerCreateSpec) (string, error) {
	if strings.TrimSpace(spec.Image) == "" {
		return "", fmt.Errorf("image is required")
	}

	exposed := nat.PortSet{}
	bindings := nat.PortMap{}
	for _, p := range spec.Ports {
		proto := p.Proto
		if proto == "" {
			proto = "tcp"
		}
		port, err := nat.NewPort(proto, fmt.Sprintf("%d", p.Container))
		if err != nil {
			return "", fmt.Errorf("invalid port %d/%s: %w", p.Container, proto, err)
		}
		exposed[port] = struct{}{}
		bindings[port] = []nat.PortBinding{{HostIP: "0.0.0.0", HostPort: fmt.Sprintf("%d", p.Host)}}
	}

	binds := make([]string, 0, len(spec.Volumes))
	for _, v := range spec.Volumes {
		bind := v.Source + ":" + v.Target
		if v.Mode != "" {
			bind += ":" + v.Mode
		}
		binds = append(binds, bind)
	}

	cfg := &containertypes.Config{
		Image:        spec.Image,
		Cmd:          spec.Command,
		Env:          spec.Env,
		Labels:       spec.Labels,
		WorkingDir:   spec.WorkingDir,
		ExposedPorts: exposed,
	}
	hostCfg := &containertypes.HostConfig{
		PortBindings: bindings,
		Binds:        binds,
		RestartPolicy: containertypes.RestartPolicy{
			Name: spec.RestartPolicy,
		},
	}
	var netCfg *networktypes.NetworkingConfig
	if spec.Network != "" {
		netCfg = &networktypes.NetworkingConfig{
			EndpointsConfig: map[string]*networktypes.EndpointSettings{
				spec.Network: {},
			},
		}
	}
	resp, err := c.cli.ContainerCreate(ctx, cfg, hostCfg, netCfg, nil, spec.Name)
	if err != nil {
		return "", err
	}
	return resp.ID, nil
}

// ContainerExecResult is the bounded result of an exec call.
type ContainerExecResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

// ExecContainer runs a command inside a running container, captures
// stdout/stderr (capped to outputCap bytes), and returns the exit code.
// User and WorkingDir are optional; pass an empty string to inherit.
func (c *Client) ExecContainer(ctx context.Context, id string, cmd []string, user, workingDir string, outputCap int) (ContainerExecResult, error) {
	if outputCap <= 0 {
		outputCap = 1024 * 1024 // 1MB default
	}
	createResp, err := c.cli.ContainerExecCreate(ctx, id, types.ExecConfig{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
		User:         user,
		WorkingDir:   workingDir,
	})
	if err != nil {
		return ContainerExecResult{}, err
	}
	hijack, err := c.cli.ContainerExecAttach(ctx, createResp.ID, types.ExecStartCheck{})
	if err != nil {
		return ContainerExecResult{}, err
	}
	defer hijack.Close()

	// Read multiplexed stream: docker frames stdout/stderr together
	// with an 8-byte header. stdcopy.StdCopy demultiplexes, but to
	// avoid an extra import we use a bounded ReadAll and ship the raw
	// stream — the panel only needs the combined output anyway.
	buf := &boundedBuffer{cap: outputCap}
	_, _ = io.Copy(buf, hijack.Reader)

	insp, err := c.cli.ContainerExecInspect(ctx, createResp.ID)
	if err != nil {
		return ContainerExecResult{}, err
	}
	return ContainerExecResult{
		Stdout:   buf.String(),
		ExitCode: insp.ExitCode,
	}, nil
}

// boundedBuffer is a tiny io.Writer that drops bytes past a cap. Used
// instead of bytes.Buffer to keep exec output from blowing memory on a
// chatty command like `find /`.
type boundedBuffer struct {
	cap  int
	data []byte
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.cap - len(b.data)
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		b.data = append(b.data, p[:remaining]...)
		return len(p), nil
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *boundedBuffer) String() string { return string(b.data) }

// ImageBuildSpec carries the curated input for BuildImage.
type ImageBuildSpec struct {
	ContextPath string            `json:"context_path"`
	Dockerfile  string            `json:"dockerfile,omitempty"`
	Tag         string            `json:"tag"`
	BuildArgs   map[string]string `json:"build_args,omitempty"`
	NoCache     bool              `json:"no_cache,omitempty"`
	Pull        bool              `json:"pull,omitempty"`
}

// BuildImageCmd builds the *exec.Cmd for a `docker build` invocation
// based on spec. The caller streams stdout/stderr (we use the same
// jobs streaming helper as packages). Returning a Cmd rather than a
// reader keeps this file from importing the docker SDK's archive
// package, which pulls in containerd/moby deps that aren't in our
// go.mod.
func (c *Client) BuildImageCmd(ctx context.Context, spec ImageBuildSpec) (*exec.Cmd, error) {
	if strings.TrimSpace(spec.ContextPath) == "" {
		return nil, fmt.Errorf("context_path is required")
	}
	if strings.TrimSpace(spec.Tag) == "" {
		return nil, fmt.Errorf("tag is required")
	}
	args := []string{"build", "-t", spec.Tag}
	if spec.Dockerfile != "" {
		args = append(args, "-f", spec.Dockerfile)
	}
	for k, v := range spec.BuildArgs {
		args = append(args, "--build-arg", k+"="+v)
	}
	if spec.NoCache {
		args = append(args, "--no-cache")
	}
	if spec.Pull {
		args = append(args, "--pull")
	}
	args = append(args, spec.ContextPath)
	return exec.CommandContext(ctx, "docker", args...), nil
}

// NetworkCreateSpec carries curated input for CreateNetwork.
type NetworkCreateSpec struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver,omitempty"` // bridge (default), overlay, host
	Internal   bool              `json:"internal,omitempty"`
	Attachable bool              `json:"attachable,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// CreateNetwork creates a Docker network and returns its ID.
func (c *Client) CreateNetwork(ctx context.Context, spec NetworkCreateSpec) (string, error) {
	if strings.TrimSpace(spec.Name) == "" {
		return "", fmt.Errorf("name is required")
	}
	driver := spec.Driver
	if driver == "" {
		driver = "bridge"
	}
	resp, err := c.cli.NetworkCreate(ctx, spec.Name, types.NetworkCreate{
		Driver:     driver,
		Internal:   spec.Internal,
		Attachable: spec.Attachable,
		Labels:     spec.Labels,
	})
	if err != nil {
		return "", err
	}
	return resp.ID, nil
}

// calculateCPUPercent calculates CPU usage percentage
func calculateCPUPercent(stats *types.StatsJSON) float64 {
	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemUsage - stats.PreCPUStats.SystemUsage)

	if systemDelta > 0 && cpuDelta > 0 {
		cpuPercent := (cpuDelta / systemDelta) * float64(stats.CPUStats.OnlineCPUs) * 100.0
		return cpuPercent
	}

	return 0.0
}

// ==================== Docker Compose ====================

// ComposeProject represents a Docker Compose project
type ComposeProject struct {
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	ConfigFiles string   `json:"config_files"`
}

// ComposeContainer represents a container in a compose project
type ComposeContainer struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Service string `json:"service"`
	State   string `json:"state"`
	Status  string `json:"status"`
	Ports   string `json:"ports"`
}

// ComposeList lists all compose projects
func (c *Client) ComposeList(ctx context.Context) ([]ComposeProject, error) {
	cmd := exec.CommandContext(ctx, "docker", "compose", "ls", "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list compose projects: %w", err)
	}

	var projects []ComposeProject
	if err := json.Unmarshal(output, &projects); err != nil {
		return nil, fmt.Errorf("failed to parse compose projects: %w", err)
	}

	return projects, nil
}

// ComposePsProject lists containers for a specific compose project
func (c *Client) ComposePsProject(ctx context.Context, projectPath string) ([]ComposeContainer, error) {
	if err := validateProjectPath(projectPath); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", projectPath, "ps", "--format", "json", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list compose containers: %w", err)
	}

	// Handle empty output
	if len(output) == 0 {
		return []ComposeContainer{}, nil
	}

	// Docker compose ps can return either a JSON array or line-delimited JSON objects
	var containers []ComposeContainer

	// Try parsing as JSON array first
	if err := json.Unmarshal(output, &containers); err != nil {
		// Try line-by-line JSON parsing
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var container ComposeContainer
			if err := json.Unmarshal([]byte(line), &container); err != nil {
				continue
			}
			containers = append(containers, container)
		}
	}

	return containers, nil
}

// ComposeUp starts a compose project
func (c *Client) ComposeUp(ctx context.Context, projectPath string, detach, build bool) (string, error) {
	if err := validateProjectPath(projectPath); err != nil {
		return "", err
	}

	args := []string{"compose", "-f", projectPath, "up"}
	if detach {
		args = append(args, "-d")
	}
	if build {
		args = append(args, "--build")
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("compose up failed: %w: %s", err, output)
	}

	return string(output), nil
}

// ComposeDown stops a compose project
func (c *Client) ComposeDown(ctx context.Context, projectPath string, volumes, removeOrphans bool) (string, error) {
	if err := validateProjectPath(projectPath); err != nil {
		return "", err
	}

	args := []string{"compose", "-f", projectPath, "down"}
	if volumes {
		args = append(args, "-v")
	}
	if removeOrphans {
		args = append(args, "--remove-orphans")
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("compose down failed: %w: %s", err, output)
	}

	return string(output), nil
}

// ComposeLogs gets logs from a compose project
func (c *Client) ComposeLogs(ctx context.Context, projectPath, service string, tail int) (string, error) {
	if err := validateProjectPath(projectPath); err != nil {
		return "", err
	}

	args := []string{"compose", "-f", projectPath, "logs", "--no-color"}
	if tail > 0 {
		args = append(args, "--tail", fmt.Sprintf("%d", tail))
	}
	if service != "" {
		args = append(args, service)
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("compose logs failed: %w: %s", err, output)
	}

	return string(output), nil
}

// ComposeRestart restarts a compose project or specific service
func (c *Client) ComposeRestart(ctx context.Context, projectPath, service string) (string, error) {
	if err := validateProjectPath(projectPath); err != nil {
		return "", err
	}

	args := []string{"compose", "-f", projectPath, "restart"}
	if service != "" {
		args = append(args, service)
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("compose restart failed: %w: %s", err, output)
	}

	return string(output), nil
}

// ComposePull pulls images for a compose project
func (c *Client) ComposePull(ctx context.Context, projectPath, service string) (string, error) {
	if err := validateProjectPath(projectPath); err != nil {
		return "", err
	}

	args := []string{"compose", "-f", projectPath, "pull"}
	if service != "" {
		args = append(args, service)
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("compose pull failed: %w: %s", err, output)
	}

	return string(output), nil
}

// validateProjectPath is a syntactic sanity check on a compose project path
// (non-empty, absolute, no `..` traversal). It is NOT the authorization
// boundary: the real restriction to the operator-configured roots is the
// symlink-resolved allowlist in the agent layer
// (agent.validateFileAccess → resolveSymlinkPath/pathWithinAllowedRoot),
// which every compose handler in internal/agent/agent.go runs on the
// project_path BEFORE calling these Compose* methods. Any NEW caller of the
// Compose* API must perform that AllowedPaths check first — this function
// alone does not confine paths to AllowedPaths.
func validateProjectPath(projectPath string) error {
	if projectPath == "" {
		return fmt.Errorf("project path is required")
	}

	// Check for path traversal attempts
	if strings.Contains(projectPath, "..") {
		return fmt.Errorf("invalid project path: path traversal not allowed")
	}

	// Check if path is absolute
	if !strings.HasPrefix(projectPath, "/") {
		return fmt.Errorf("invalid project path: must be absolute path")
	}

	return nil
}

