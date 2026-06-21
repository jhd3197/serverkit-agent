package tray

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/ipc"
)

// Client communicates with the agent's IPC server
type Client struct {
	baseURL    string
	httpClient *http.Client
	// token is the bearer credential the IPC server requires on every
	// endpoint except /health. Loaded lazily from disk on each request
	// so the tray picks up token rotations without restart. An empty
	// token still lets /health probes work (the only endpoint the
	// IPC server leaves unauthenticated), but every other call will
	// 401 — IsAgentRunning() therefore stays accurate.
	token string
}

// NewClient creates a new IPC client
func NewClient(address string, port int) *Client {
	return &Client{
		baseURL: fmt.Sprintf("http://%s:%d", address, port),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// loadToken reads the IPC token from the well-known path the agent
// service writes on startup. Best-effort: a missing file just means
// "agent never finished initialising the IPC server" — the caller
// gets a 401 and surfaces it as an unreachable agent.
func (c *Client) loadToken() string {
	if data, err := os.ReadFile(config.IPCTokenPath()); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

// authedRequest builds a GET/POST with the Authorization header set.
// Centralising the header lets us swap to a different scheme later
// without touching every endpoint method.
func (c *Client) authedRequest(method, url string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	if tok := c.loadToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return req, nil
}

// GetStatus fetches the agent status
func (c *Client) GetStatus() (*ipc.AgentStatus, error) {
	req, err := c.authedRequest(http.MethodGet, c.baseURL+"/status")
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var status ipc.AgentStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}

	return &status, nil
}

// GetMetrics fetches detailed system metrics
func (c *Client) GetMetrics() (*ipc.DetailedMetrics, error) {
	req, err := c.authedRequest(http.MethodGet, c.baseURL+"/metrics")
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var metrics ipc.DetailedMetrics
	if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
		return nil, err
	}

	return &metrics, nil
}

// GetConnection fetches WebSocket connection info
func (c *Client) GetConnection() (*ipc.ConnectionInfo, error) {
	req, err := c.authedRequest(http.MethodGet, c.baseURL+"/connection")
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var info ipc.ConnectionInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	return &info, nil
}

// GetLogs fetches recent log lines
func (c *Client) GetLogs(lines int) ([]string, error) {
	req, err := c.authedRequest(http.MethodGet, fmt.Sprintf("%s/logs?lines=%d", c.baseURL, lines))
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result struct {
		Lines []string `json:"lines"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Lines, nil
}

// Restart requests agent restart
func (c *Client) Restart() error {
	req, err := c.authedRequest(http.MethodPost, c.baseURL+"/restart")
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result struct {
		Success bool   `json:"success"`
		Error   string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("restart failed: %s", result.Error)
	}

	return nil
}

// IsAgentRunning checks if the agent is reachable
func (c *Client) IsAgentRunning() bool {
	resp, err := c.httpClient.Get(c.baseURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
