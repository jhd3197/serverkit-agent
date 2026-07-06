// Package survey implements the read-only "flight" the panel dispatches
// via survey:read (plan 27 Phase 2, agent side in plan 28 Phase 4). The
// panel is UNTRUSTED here (docs/AGENT_SURVEY_SPEC.md, Decision 2): it
// ships a declarative probe catalog, but the agent executes it against a
// FIXED allowlist of read-only primitives. A catalog can only COMBINE the
// primitives — it can never name a shell command, a binary to run, or a
// file whose contents leave the box wholesale. Anything a catalog entry
// asks for outside the allowlist is refused per-entry (skip + note),
// never executed, and never fails the whole survey.
//
// The response is a SYNCHRONOUS command result (the poll transport drops
// streams), size-capped and always partial-safe — the panel's
// normalize_map is defensive by design.
package survey

import (
	"context"
	"strings"
)

// Caps for the whole response, defensive against a pathological catalog
// or a box with thousands of vhosts/containers/sockets. The panel's
// normalize_map handles a truncated payload fine; a silent cap is logged
// by the caller, not here.
const (
	maxVhostsPerProbe  = 200
	maxContainers      = 100
	maxListeners       = 500
	maxProcessNames    = 500
	maxCerts           = 200
	maxCrontabLines    = 500
	maxGlobMatches     = 500
	maxMarkers         = 50
	maxResponseBytes   = 256 * 1024 // soft cap, mirrors packages:list_installed
	maxParseFileBytes  = 1024 * 1024
	maxStringFieldRunes = 512
)

// Catalog is the untrusted probe catalog the panel sends verbatim.
type Catalog struct {
	Version int     `json:"version"`
	Probes  []Probe `json:"probes"`
}

// Probe is one catalog entry. Only the fields the allowlisted primitives
// consume are read; unknown fields are ignored.
type Probe struct {
	ID     string              `json:"id"`
	Kind   string              `json:"kind"`
	Title  string              `json:"title"`
	Detect Detect              `json:"detect"`
	Map    map[string][]string `json:"map"`
}

// Detect is the presence-check block: any positive signal marks the probe
// detected. All fields optional.
type Detect struct {
	Ports []int    `json:"ports"`
	Units []string `json:"units"`
	Bins  []string `json:"bins"`
	Paths []string `json:"paths"`
}

// Vhost is a parse-light-extracted web server virtual host. upstream
// (proxy_pass) present with no root ⇒ the panel treats it as a reverse
// proxy.
type Vhost struct {
	ServerName string `json:"server_name,omitempty"`
	Root       string `json:"root,omitempty"`
	Upstream   string `json:"upstream,omitempty"`
}

// Container is one running docker container (name/image/ports only).
type Container struct {
	Name  string   `json:"name"`
	Image string   `json:"image,omitempty"`
	Ports []string `json:"ports,omitempty"`
}

// Listener is one listening socket mapped to the owning process NAME
// (never its command line or environment).
type Listener struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto,omitempty"`
	Process string `json:"process,omitempty"`
}

// Cert is cert-meta: subject/SAN domains + expiry. Private keys are never
// read.
type Cert struct {
	Domain    string `json:"domain"`
	ExpiresAt string `json:"expires_at,omitempty"` // ISO-8601
}

// HostProbes are the host-dependent primitives (systemd, sockets,
// processes, docker). Split behind an interface so the catalog
// interpreter is testable without a live host. The production
// implementation is LiveProbes; tests inject a fake.
type HostProbes interface {
	// UnitActive reports (active, ActiveState) for a systemd unit.
	UnitActive(ctx context.Context, unit string) (bool, string)
	// Listeners returns listening sockets → {port, proto, process-name}.
	Listeners(ctx context.Context) []Listener
	// ProcessNames returns running process NAMES only.
	ProcessNames(ctx context.Context) []string
	// DockerContainers returns running containers, or nil when docker is
	// unavailable on this host.
	DockerContainers(ctx context.Context) []Container
}

// Executor runs a catalog against the primitives.
type Executor struct {
	probes HostProbes
}

// NewExecutor builds an Executor over the given host probes.
func NewExecutor(probes HostProbes) *Executor {
	return &Executor{probes: probes}
}

// Run interprets the catalog and returns the survey `data` payload keyed
// by probe id (docs/AGENT_SURVEY_SPEC.md). It never returns an error for
// a bad catalog entry — that entry is refused in place. `catalog_version`
// is echoed so the panel can note a catalog change between flights.
func (e *Executor) Run(ctx context.Context, cat Catalog) map[string]interface{} {
	probes := map[string]interface{}{}
	for _, p := range cat.Probes {
		if p.ID == "" {
			continue
		}
		probes[p.ID] = e.runProbe(ctx, p)
	}
	return map[string]interface{}{
		"catalog_version": cat.Version,
		"probes":          probes,
	}
}

// runProbe dispatches one probe by kind. Unknown kinds are refused
// per-entry, never executed.
func (e *Executor) runProbe(ctx context.Context, p Probe) map[string]interface{} {
	switch p.Kind {
	case "service+config":
		return e.serviceConfigProbe(ctx, p)
	case "service":
		return e.serviceProbe(ctx, p)
	case "marker":
		return e.markerProbe(p)
	case "inventory":
		return e.inventoryProbe(ctx, p)
	default:
		return map[string]interface{}{
			"detected": false,
			"refused":  "unknown probe kind: " + p.Kind,
		}
	}
}

// detect runs the presence checks. Any positive signal ⇒ detected. Also
// returns which detect.ports are actually listening (for the service
// block) and whether any detect.unit is active.
func (e *Executor) detect(ctx context.Context, p Probe) (detected, anyUnitActive bool, activePorts []int) {
	for _, u := range p.Detect.Units {
		// Skip glob-ish unit patterns (e.g. "php*-fpm") for the active
		// check — the panel's catalog uses them but is-active needs a
		// concrete unit; presence is still established by bins/paths.
		if strings.ContainsAny(u, "*?[") {
			continue
		}
		if active, _ := e.probes.UnitActive(ctx, u); active {
			detected = true
			anyUnitActive = true
		}
	}
	for _, b := range p.Detect.Bins {
		if binOnPath(b) {
			detected = true
		}
	}
	for _, path := range p.Detect.Paths {
		if ok, _ := fileExists(path); ok {
			detected = true
		}
	}
	if len(p.Detect.Ports) > 0 {
		listening := listeningPorts(e.probes.Listeners(ctx))
		for _, port := range p.Detect.Ports {
			if listening[port] {
				detected = true
				activePorts = append(activePorts, port)
			}
		}
	}
	return detected, anyUnitActive, activePorts
}

// serviceConfigProbe handles nginx / apache / php-fpm: detection + service
// block + parse-light vhosts from the map globs.
func (e *Executor) serviceConfigProbe(ctx context.Context, p Probe) map[string]interface{} {
	detected, active, ports := e.detect(ctx, p)
	out := map[string]interface{}{"detected": detected}
	if !detected {
		return out
	}
	svc := map[string]interface{}{"active": active}
	if len(ports) > 0 {
		svc["ports"] = ports
	}
	out["service"] = svc

	// vhost extraction is parse-light: only whitelisted directives, line
	// scanned, never whole-file. Choose the directive set by id.
	directives := nginxDirectives
	if p.ID == "apache" {
		directives = apacheDirectives
	}
	var vhosts []Vhost
	for _, pattern := range p.Map["vhosts"] {
		for _, path := range globPaths(pattern, maxGlobMatches) {
			vhosts = append(vhosts, parseVhosts(path, directives)...)
			if len(vhosts) >= maxVhostsPerProbe {
				vhosts = vhosts[:maxVhostsPerProbe]
				break
			}
		}
	}
	if len(vhosts) > 0 {
		out["vhosts"] = vhosts
	}
	return out
}

// serviceProbe handles docker / databases / mail. Detection + service
// block, plus id-specific collections the panel consumes.
func (e *Executor) serviceProbe(ctx context.Context, p Probe) map[string]interface{} {
	detected, active, ports := e.detect(ctx, p)
	out := map[string]interface{}{"detected": detected}
	if !detected {
		return out
	}
	out["service"] = map[string]interface{}{"active": active}

	switch p.ID {
	case "docker":
		containers := e.probes.DockerContainers(ctx)
		if len(containers) > maxContainers {
			containers = containers[:maxContainers]
		}
		if containers != nil {
			out["containers"] = containers
		}
	case "databases":
		engines := e.databaseEngines(ctx, p)
		if len(engines) > 0 {
			out["engines"] = engines
		}
	default:
		// mail and any other plain service: detected + service is enough;
		// surface listening ports informationally.
		if len(ports) > 0 {
			out["ports"] = ports
		}
	}
	return out
}

// markerProbe handles foreign-panel: existence-only marker directories.
// Contents are never read (Decision 4 — SUGGESTS Observed, never flips).
func (e *Executor) markerProbe(p Probe) map[string]interface{} {
	var markers []string
	for _, path := range p.Detect.Paths {
		if ok, _ := fileExists(path); ok {
			markers = append(markers, truncateStr(path))
			if len(markers) >= maxMarkers {
				break
			}
		}
	}
	out := map[string]interface{}{"detected": len(markers) > 0}
	if len(markers) > 0 {
		out["markers"] = markers
	}
	return out
}

// inventoryProbe handles crontabs / certs / listeners.
func (e *Executor) inventoryProbe(ctx context.Context, p Probe) map[string]interface{} {
	switch p.ID {
	case "listeners":
		ls := e.probes.Listeners(ctx)
		if len(ls) > maxListeners {
			ls = ls[:maxListeners]
		}
		return map[string]interface{}{"listeners": ls}
	case "certs":
		var certs []Cert
		for _, pattern := range p.Map["certs"] {
			for _, path := range globPaths(pattern, maxGlobMatches) {
				if c, ok := certMeta(path); ok {
					certs = append(certs, c)
				}
				if len(certs) >= maxCerts {
					break
				}
			}
		}
		out := map[string]interface{}{"detected": len(certs) > 0}
		if len(certs) > 0 {
			out["certs"] = certs
		}
		return out
	case "crontabs":
		// v1: the AGENT USER's crontab only (reading other users' tables
		// needs root — deferred). Schedule lines only, parse-light.
		lines := agentCrontabLines(ctx, maxCrontabLines)
		out := map[string]interface{}{}
		if len(lines) > 0 {
			out["crontabs"] = []map[string]interface{}{
				{"user": currentUsername(), "lines": lines},
			}
		}
		return out
	default:
		return map[string]interface{}{"refused": "unknown inventory probe: " + p.ID}
	}
}

// databaseEngines maps detected database units to {name, active, port}.
// Engine → default port is a small fixed table; the catalog supplies the
// unit names (data), the agent supplies the port knowledge (code).
func (e *Executor) databaseEngines(ctx context.Context, p Probe) []map[string]interface{} {
	var engines []map[string]interface{}
	seen := map[string]bool{}
	for _, unit := range p.Detect.Units {
		if strings.ContainsAny(unit, "*?[") {
			continue
		}
		name := engineName(unit)
		if seen[name] {
			continue
		}
		active, _ := e.probes.UnitActive(ctx, unit)
		entry := map[string]interface{}{"name": name, "active": active}
		if port := enginePort(name); port > 0 {
			entry["port"] = port
		}
		engines = append(engines, entry)
		seen[name] = true
	}
	return engines
}

// listeningPorts collapses a listener slice into a port→true set.
func listeningPorts(ls []Listener) map[int]bool {
	set := map[int]bool{}
	for _, l := range ls {
		set[l.Port] = true
	}
	return set
}

// engineName normalizes a db unit name (mariadb→mysql-ish label kept
// distinct; postgresql→postgres). Returns the canonical engine label.
func engineName(unit string) string {
	switch unit {
	case "mysql", "mysqld":
		return "mysql"
	case "mariadb", "mariadbd":
		return "mariadb"
	case "postgresql", "postgres":
		return "postgres"
	case "mongod", "mongodb":
		return "mongodb"
	}
	return unit
}

func enginePort(name string) int {
	switch name {
	case "mysql", "mariadb":
		return 3306
	case "postgres":
		return 5432
	case "mongodb":
		return 27017
	}
	return 0
}

var (
	nginxDirectives  = []string{"server_name", "root", "proxy_pass"}
	apacheDirectives = []string{"ServerName", "DocumentRoot", "ProxyPass"}
)
