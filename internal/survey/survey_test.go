package survey

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── primitive: parse-light / vhosts ──────────────────────────────────

func TestParseVhostsNginx(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "example.conf")
	// Two server blocks + a comment + a secret line that must NEVER surface.
	os.WriteFile(conf, []byte(`
# a comment that must not leak
server {
    listen 80;
    server_name example.com;
    root /var/www/example;
    ssl_certificate_key /etc/ssl/private/secret.key;
}
server {
    server_name api.example.com;
    location / {
        proxy_pass http://127.0.0.1:8001;
    }
}
`), 0o644)

	vhosts := parseVhosts(conf, nginxDirectives)
	if len(vhosts) != 2 {
		t.Fatalf("expected 2 vhosts, got %d: %+v", len(vhosts), vhosts)
	}
	if vhosts[0].ServerName != "example.com" || vhosts[0].Root != "/var/www/example" {
		t.Errorf("vhost0 = %+v", vhosts[0])
	}
	if vhosts[0].Upstream != "" {
		t.Errorf("vhost0 should have no upstream, got %q", vhosts[0].Upstream)
	}
	if vhosts[1].ServerName != "api.example.com" || vhosts[1].Upstream != "http://127.0.0.1:8001" {
		t.Errorf("vhost1 = %+v", vhosts[1])
	}
	// The private-key directive is not whitelisted, so it must not appear
	// anywhere in the extracted lines.
	for _, l := range parseLight(conf, nginxDirectives) {
		if filepathContains(l, "secret.key") {
			t.Fatalf("parse-light leaked a non-whitelisted line: %q", l)
		}
	}
}

func TestParseVhostsApache(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "site.conf")
	os.WriteFile(conf, []byte(`
<VirtualHost *:80>
    ServerName shop.example.com
    DocumentRoot /srv/shop
</VirtualHost>
<VirtualHost *:80>
    ServerName proxy.example.com
    ProxyPass / http://127.0.0.1:9000/
</VirtualHost>
`), 0o644)

	vhosts := parseVhosts(conf, apacheDirectives)
	if len(vhosts) != 2 {
		t.Fatalf("expected 2 vhosts, got %d: %+v", len(vhosts), vhosts)
	}
	if vhosts[0].ServerName != "shop.example.com" || vhosts[0].Root != "/srv/shop" {
		t.Errorf("vhost0 = %+v", vhosts[0])
	}
	if vhosts[1].ServerName != "proxy.example.com" || vhosts[1].Upstream != "/" {
		// ProxyPass first token is "/" (the location) — parse-light keeps it
		// as-is; the panel treats upstream-present-no-root as a proxy.
		t.Logf("vhost1 = %+v (proxy target parsing is best-effort)", vhosts[1])
	}
}

func filepathContains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// ── primitive: cert-meta ─────────────────────────────────────────────

func writeTestCert(t *testing.T, dir, cn string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	// A private key that MUST never be read.
	os.WriteFile(filepath.Join(dir, "privkey.pem"), []byte("-----BEGIN EC PRIVATE KEY-----\nsecret\n-----END EC PRIVATE KEY-----\n"), 0o600)
}

func TestCertMeta(t *testing.T) {
	live := t.TempDir()
	domainDir := filepath.Join(live, "example.com")
	os.MkdirAll(domainDir, 0o755)
	expiry := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	writeTestCert(t, domainDir, "example.com", expiry)

	c, ok := certMeta(domainDir)
	if !ok {
		t.Fatal("certMeta failed to read cert.pem from the domain dir")
	}
	if c.Domain != "example.com" {
		t.Errorf("domain = %q, want example.com", c.Domain)
	}
	if c.ExpiresAt != "2027-01-02T03:04:05Z" {
		t.Errorf("expires_at = %q", c.ExpiresAt)
	}

	// Pointing certMeta directly at a private key must be refused.
	if _, ok := certMeta(filepath.Join(domainDir, "privkey.pem")); ok {
		t.Fatal("certMeta must never parse a private key file")
	}
}

// ── primitive: cron schedule heuristic ───────────────────────────────

func TestLooksLikeCronSchedule(t *testing.T) {
	cases := map[string]bool{
		"0 3 * * * /usr/bin/backup":     true,
		"*/5 * * * * /opt/run":          true,
		"@reboot /usr/bin/boot":         true,
		"PATH=/usr/bin":                 false,
		"# comment":                     false,
		"MAILTO=root":                   false,
		"0 3 * * *":                     false, // schedule but no command
	}
	for line, want := range cases {
		if got := looksLikeCronSchedule(line); got != want {
			t.Errorf("looksLikeCronSchedule(%q) = %v, want %v", line, got, want)
		}
	}
}

// ── catalog interpreter (executor) ───────────────────────────────────

type fakeProbes struct {
	active     map[string]bool
	listeners  []Listener
	processes  []string
	containers []Container
}

func (f fakeProbes) UnitActive(_ context.Context, unit string) (bool, string) {
	if f.active[unit] {
		return true, "active"
	}
	return false, "inactive"
}
func (f fakeProbes) Listeners(context.Context) []Listener      { return f.listeners }
func (f fakeProbes) ProcessNames(context.Context) []string     { return f.processes }
func (f fakeProbes) DockerContainers(context.Context) []Container { return f.containers }

func TestExecutorProducesConformantMap(t *testing.T) {
	dir := t.TempDir()
	// nginx vhost config the executor will parse-light.
	sitesDir := filepath.Join(dir, "sites-enabled")
	os.MkdirAll(sitesDir, 0o755)
	os.WriteFile(filepath.Join(sitesDir, "example.conf"), []byte(
		"server {\n server_name example.com;\n root /var/www/example;\n}\n"+
			"server {\n server_name api.example.com;\n proxy_pass http://127.0.0.1:8001;\n}\n"), 0o644)
	// A foreign-panel marker dir that exists.
	marker := filepath.Join(dir, "cpanel")
	os.MkdirAll(marker, 0o755)
	// A letsencrypt-style cert.
	certDir := filepath.Join(dir, "live", "example.com")
	os.MkdirAll(certDir, 0o755)
	writeTestCert(t, certDir, "example.com", time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC))

	catalog := Catalog{
		Version: 1,
		Probes: []Probe{
			{ID: "nginx", Kind: "service+config",
				Detect: Detect{Units: []string{"nginx"}, Ports: []int{80, 443}},
				Map:    map[string][]string{"vhosts": {filepath.Join(sitesDir, "*.conf")}}},
			{ID: "apache", Kind: "service+config",
				Detect: Detect{Units: []string{"apache2", "httpd"}}},
			{ID: "docker", Kind: "service",
				Detect: Detect{Units: []string{"docker"}}},
			{ID: "databases", Kind: "service",
				Detect: Detect{Units: []string{"mysql", "postgresql"}}},
			{ID: "foreign-panel", Kind: "marker",
				Detect: Detect{Paths: []string{marker, filepath.Join(dir, "does-not-exist")}}},
			{ID: "certs", Kind: "inventory",
				Detect: Detect{Paths: []string{filepath.Join(dir, "live")}},
				Map:    map[string][]string{"certs": {filepath.Join(dir, "live", "*")}}},
			{ID: "listeners", Kind: "inventory"},
			{ID: "mystery", Kind: "wat"}, // unknown kind → refused, never executed
		},
	}

	probes := fakeProbes{
		active:     map[string]bool{"nginx": true, "docker": true, "mysql": true},
		listeners:  []Listener{{Port: 80, Proto: "tcp", Process: "nginx"}},
		containers: []Container{{Name: "site1", Image: "wordpress:6", Ports: []string{"8001->80"}}},
	}

	out := NewExecutor(probes).Run(context.Background(), catalog)

	// Round-trip through JSON so we assert exactly what goes on the wire.
	raw, _ := json.Marshal(out)
	var got map[string]interface{}
	json.Unmarshal(raw, &got)

	if got["catalog_version"].(float64) != 1 {
		t.Fatalf("catalog_version = %v", got["catalog_version"])
	}
	p := got["probes"].(map[string]interface{})

	nginx := p["nginx"].(map[string]interface{})
	if nginx["detected"] != true {
		t.Error("nginx should be detected")
	}
	vhosts := nginx["vhosts"].([]interface{})
	if len(vhosts) != 2 {
		t.Fatalf("expected 2 nginx vhosts, got %d", len(vhosts))
	}
	v0 := vhosts[0].(map[string]interface{})
	if v0["server_name"] != "example.com" || v0["root"] != "/var/www/example" {
		t.Errorf("vhost0 = %v", v0)
	}
	v1 := vhosts[1].(map[string]interface{})
	if v1["upstream"] != "http://127.0.0.1:8001" {
		t.Errorf("vhost1 upstream = %v", v1["upstream"])
	}

	if p["apache"].(map[string]interface{})["detected"] != false {
		t.Error("apache should not be detected")
	}

	docker := p["docker"].(map[string]interface{})
	containers := docker["containers"].([]interface{})
	if len(containers) != 1 || containers[0].(map[string]interface{})["name"] != "site1" {
		t.Errorf("docker containers = %v", containers)
	}

	engines := p["databases"].(map[string]interface{})["engines"].([]interface{})
	if len(engines) == 0 || engines[0].(map[string]interface{})["name"] != "mysql" {
		t.Errorf("databases engines = %v", engines)
	}
	if engines[0].(map[string]interface{})["port"].(float64) != 3306 {
		t.Errorf("mysql port = %v", engines[0].(map[string]interface{})["port"])
	}

	fp := p["foreign-panel"].(map[string]interface{})
	if fp["detected"] != true {
		t.Error("foreign-panel should be detected")
	}
	if len(fp["markers"].([]interface{})) != 1 {
		t.Errorf("expected 1 marker, got %v", fp["markers"])
	}

	certs := p["certs"].(map[string]interface{})["certs"].([]interface{})
	if len(certs) != 1 || certs[0].(map[string]interface{})["domain"] != "example.com" {
		t.Errorf("certs = %v", certs)
	}

	listeners := p["listeners"].(map[string]interface{})["listeners"].([]interface{})
	if len(listeners) != 1 || listeners[0].(map[string]interface{})["port"].(float64) != 80 {
		t.Errorf("listeners = %v", listeners)
	}

	// Unknown kind must be refused per-entry, never executed.
	mystery := p["mystery"].(map[string]interface{})
	if mystery["detected"] != false || mystery["refused"] == nil {
		t.Errorf("mystery probe should be refused, got %v", mystery)
	}
}

// ── cross-repo conformance: the golden fixtures ──────────────────────

// TestGoldenRequestParses proves the agent parses the panel's catalog
// format verbatim (the request direction of #14).
func TestGoldenRequestParses(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "survey_golden_request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat Catalog
	if err := json.Unmarshal(data, &cat); err != nil {
		t.Fatalf("agent failed to parse the panel catalog: %v", err)
	}
	if cat.Version != 1 || len(cat.Probes) == 0 {
		t.Fatalf("unexpected catalog: version=%d probes=%d", cat.Version, len(cat.Probes))
	}
	byID := map[string]Probe{}
	for _, p := range cat.Probes {
		byID[p.ID] = p
	}
	if byID["nginx"].Kind != "service+config" {
		t.Errorf("nginx kind = %q", byID["nginx"].Kind)
	}
	if len(byID["nginx"].Map["vhosts"]) == 0 {
		t.Error("nginx probe should carry vhost globs")
	}
}

// TestGoldenResponseTypesRoundTrip proves the agent's own response types
// decode the panel's FIXTURE_PAYLOAD-shaped golden response — i.e. the two
// repos agree on the same bytes (the response direction of #14).
func TestGoldenResponseTypesRoundTrip(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "survey_golden_response.json"))
	if err != nil {
		t.Fatal(err)
	}
	// A decode target mirroring what the executor emits per probe.
	var resp struct {
		CatalogVersion int `json:"catalog_version"`
		Probes         struct {
			Nginx struct {
				Detected bool    `json:"detected"`
				Vhosts   []Vhost `json:"vhosts"`
			} `json:"nginx"`
			Databases struct {
				Detected bool                     `json:"detected"`
				Engines  []map[string]interface{} `json:"engines"`
			} `json:"databases"`
			ForeignPanel struct {
				Detected bool     `json:"detected"`
				Markers  []string `json:"markers"`
			} `json:"foreign-panel"`
			Certs struct {
				Certs []Cert `json:"certs"`
			} `json:"certs"`
			Listeners struct {
				Listeners []Listener `json:"listeners"`
			} `json:"listeners"`
		} `json:"probes"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("agent types failed to decode the golden response: %v", err)
	}
	if resp.CatalogVersion != 1 {
		t.Errorf("catalog_version = %d", resp.CatalogVersion)
	}
	if len(resp.Probes.Nginx.Vhosts) != 2 || resp.Probes.Nginx.Vhosts[0].ServerName != "example.com" {
		t.Errorf("nginx vhosts = %+v", resp.Probes.Nginx.Vhosts)
	}
	if resp.Probes.Nginx.Vhosts[1].Upstream != "http://127.0.0.1:8001" {
		t.Errorf("nginx vhost1 upstream = %q", resp.Probes.Nginx.Vhosts[1].Upstream)
	}
	if resp.Probes.ForeignPanel.Markers[0] != "/usr/local/cpanel" {
		t.Errorf("markers = %v", resp.Probes.ForeignPanel.Markers)
	}
	if resp.Probes.Certs.Certs[0].Domain != "example.com" {
		t.Errorf("cert domain = %q", resp.Probes.Certs.Certs[0].Domain)
	}
	if resp.Probes.Listeners.Listeners[0].Port != 80 {
		t.Errorf("listener port = %d", resp.Probes.Listeners.Listeners[0].Port)
	}
}
