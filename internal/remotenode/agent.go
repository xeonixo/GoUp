package remotenode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"goup/internal/monitor"
)

type Config struct {
	ControlPlaneURL    string
	NodeID             string
	BootstrapKey       string
	InitialPollSeconds int
}

type Agent struct {
	cfg         Config
	logger      *slog.Logger
	httpClient  *http.Client
	accessToken string
	pollSeconds int
}

type bootstrapRequest struct {
	NodeID       string `json:"node_id"`
	BootstrapKey string `json:"bootstrap_key"`
}

type bootstrapResponse struct {
	OK                  bool   `json:"ok"`
	AccessToken         string `json:"access_token"`
	AccessTokenExpires  string `json:"access_token_expires"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
}

type pollResponse struct {
	OK                  bool                  `json:"ok"`
	AccessToken         string                `json:"access_token"`
	AccessTokenExpires  string                `json:"access_token_expires"`
	PollIntervalSeconds int                   `json:"poll_interval_seconds"`
	AssignedMonitors    []assignedMonitorSpec `json:"assigned_monitors"`
}

type assignedMonitorSpec struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Kind               string `json:"kind"`
	Target             string `json:"target"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
	TLSMode            string `json:"tls_mode"`
	ExpectedStatusCode *int   `json:"expected_status_code,omitempty"`
	ExpectedText       string `json:"expected_text,omitempty"`
}

type reportRequest struct {
	Results []reportResult `json:"results"`
}

type reportResult struct {
	MonitorID        int64   `json:"monitor_id"`
	CheckedAt        string  `json:"checked_at"`
	Status           string  `json:"status"`
	LatencyMS        int64   `json:"latency_ms"`
	Message          string  `json:"message"`
	HTTPStatusCode   *int    `json:"http_status_code,omitempty"`
	TLSValid         *bool   `json:"tls_valid,omitempty"`
	TLSNotAfter      *string `json:"tls_not_after,omitempty"`
	TLSDaysRemaining *int    `json:"tls_days_remaining,omitempty"`
}

func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		ControlPlaneURL:    normalizeControlPlaneURL(os.Getenv("REMOTE_NODE_CONTROL_PLANE_URL")),
		NodeID:             strings.TrimSpace(os.Getenv("REMOTE_NODE_ID")),
		BootstrapKey:       strings.TrimSpace(os.Getenv("REMOTE_NODE_BOOTSTRAP_KEY")),
		InitialPollSeconds: 20,
	}
	if cfg.ControlPlaneURL == "" || cfg.NodeID == "" || cfg.BootstrapKey == "" {
		return Config{}, errors.New("REMOTE_NODE_CONTROL_PLANE_URL, REMOTE_NODE_ID und REMOTE_NODE_BOOTSTRAP_KEY müssen gesetzt sein")
	}
	if raw := strings.TrimSpace(os.Getenv("REMOTE_NODE_POLL_SECONDS")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			cfg.InitialPollSeconds = value
		}
	}
	return cfg, nil
}

func normalizeControlPlaneURL(raw string) string {
	value := strings.TrimRight(strings.TrimSpace(raw), "/")
	for _, suffix := range []string{"/node/bootstrap", "/node/poll", "/node/report"} {
		if strings.HasSuffix(value, suffix) {
			value = strings.TrimSuffix(value, suffix)
			break
		}
	}
	return value
}

func New(cfg Config, logger *slog.Logger) *Agent {
	return &Agent{
		cfg:    cfg,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		pollSeconds: cfg.InitialPollSeconds,
	}
}

func (a *Agent) Run(ctx context.Context) error {
	if err := a.bootstrap(ctx); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		assigned, err := a.poll(ctx)
		if err != nil {
			a.logger.Error("poll failed", "error", err)
			a.sleep(ctx, time.Duration(a.pollSeconds)*time.Second)
			continue
		}

		results := a.runChecks(ctx, assigned)
		if len(results) > 0 {
			if err := a.report(ctx, results); err != nil {
				a.logger.Error("report failed", "error", err)
			}
		}

		a.sleep(ctx, time.Duration(a.pollSeconds)*time.Second)
	}
}

// sleep waits for the given duration or until ctx is cancelled.
func (a *Agent) sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func (a *Agent) bootstrap(ctx context.Context) error {
	request := bootstrapRequest{NodeID: a.cfg.NodeID, BootstrapKey: a.cfg.BootstrapKey}
	var response bootstrapResponse
	if err := a.postJSON(ctx, a.nodeEndpointURL("/node/bootstrap"), "", request, &response); err != nil {
		return err
	}
	if !response.OK || strings.TrimSpace(response.AccessToken) == "" {
		return errors.New("bootstrap response without access token")
	}
	a.accessToken = strings.TrimSpace(response.AccessToken)
	if response.PollIntervalSeconds > 0 {
		a.pollSeconds = response.PollIntervalSeconds
	}
	a.logger.Info("bootstrap successful", "node_id", a.cfg.NodeID, "poll_seconds", a.pollSeconds)
	return nil
}

func (a *Agent) poll(ctx context.Context) ([]assignedMonitorSpec, error) {
	request := map[string]any{"agent_version": "remote-node/0.1"}
	var response pollResponse
	if err := a.postJSON(ctx, a.nodeEndpointURL("/node/poll"), a.accessToken, request, &response); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "401") {
			if bootErr := a.bootstrap(ctx); bootErr != nil {
				return nil, bootErr
			}
		}
		return nil, err
	}
	if strings.TrimSpace(response.AccessToken) != "" {
		a.accessToken = strings.TrimSpace(response.AccessToken)
	}
	if response.PollIntervalSeconds > 0 {
		a.pollSeconds = response.PollIntervalSeconds
	}
	return response.AssignedMonitors, nil
}

func (a *Agent) report(ctx context.Context, results []reportResult) error {
	if len(results) == 0 {
		return nil
	}
	request := reportRequest{Results: results}
	var response map[string]any
	if err := a.postJSON(ctx, a.nodeEndpointURL("/node/report"), a.accessToken, request, &response); err != nil {
		return err
	}
	return nil
}

func (a *Agent) nodeEndpointURL(path string) string {
	return a.cfg.ControlPlaneURL + path
}

func (a *Agent) runChecks(ctx context.Context, assigned []assignedMonitorSpec) []reportResult {
	if len(assigned) == 0 {
		return nil
	}
	checkers := map[monitor.Kind]monitor.Checker{
		monitor.KindHTTPS: monitor.HTTPSChecker{},
		monitor.KindTCP:   monitor.TCPChecker{},
		monitor.KindICMP:  monitor.ICMPChecker{},
		monitor.KindSMTP:  monitor.SMTPChecker{},
		monitor.KindIMAP:  monitor.IMAPChecker{},
		monitor.KindDNS:   monitor.DNSChecker{},
		monitor.KindUDP:   monitor.UDPChecker{},
		monitor.KindWhois: monitor.WhoisChecker{},
	}

	results := make([]reportResult, 0, len(assigned))
	for _, item := range assigned {
		kind := monitor.Kind(strings.TrimSpace(item.Kind))
		checker, ok := checkers[kind]
		if !ok {
			continue
		}
		timeout := item.TimeoutSeconds
		if timeout <= 0 {
			timeout = 10
		}
		mon := monitor.Monitor{
			ID:                 item.ID,
			Name:               strings.TrimSpace(item.Name),
			Kind:               kind,
			Target:             strings.TrimSpace(item.Target),
			Timeout:            time.Duration(timeout) * time.Second,
			TLSMode:            monitor.TLSMode(strings.TrimSpace(item.TLSMode)),
			ExpectedStatusCode: item.ExpectedStatusCode,
			ExpectedText:       strings.TrimSpace(item.ExpectedText),
			Enabled:            true,
		}
		runCtx, cancel := context.WithTimeout(ctx, mon.Timeout+2*time.Second)
		res := checker.Check(runCtx, mon)
		cancel()
		payload := reportResult{
			MonitorID:        mon.ID,
			CheckedAt:        res.CheckedAt.UTC().Format(time.RFC3339),
			Status:           string(res.Status),
			LatencyMS:        res.Latency.Milliseconds(),
			Message:          strings.TrimSpace(res.Message),
			HTTPStatusCode:   res.HTTPStatusCode,
			TLSValid:         res.TLSValid,
			TLSDaysRemaining: res.TLSDaysRemaining,
		}
		if res.TLSNotAfter != nil {
			value := res.TLSNotAfter.UTC().Format(time.RFC3339)
			payload.TLSNotAfter = &value
		}
		results = append(results, payload)
	}
	return results
}

func (a *Agent) postJSON(ctx context.Context, endpoint string, bearerToken string, requestBody any, responseBody any) error {
	payload, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(bearerToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(bearerToken))
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if responseBody == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(responseBody)
}
