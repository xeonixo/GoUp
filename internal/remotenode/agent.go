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
	"strings"
	"sync"
	"time"

	"goup/internal/monitor"
)

type Agent struct {
	cfg         Config
	logger      *slog.Logger
	httpClient  *http.Client
	accessToken string
	pollSeconds int
	workerSem   chan struct{}
	scheduleMu  sync.Mutex
	schedule    map[int64]*remoteScheduleState
	assignments map[int64]assignedMonitorSpec
}

func New(cfg Config, logger *slog.Logger) *Agent {
	return &Agent{
		cfg:         cfg,
		logger:      logger,
		workerSem:   make(chan struct{}, 4),
		schedule:    make(map[int64]*remoteScheduleState),
		assignments: make(map[int64]assignedMonitorSpec),
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

	nextPoll := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			if !now.Before(nextPoll) {
				assigned, err := a.poll(ctx)
				if err != nil {
					a.logger.Error("poll failed", "error", err)
				} else {
					a.updateAssignments(assigned, now.UTC())
				}
				nextPoll = now.Add(time.Duration(a.pollSeconds) * time.Second)
			}
			a.dispatchDueChecks(ctx, now.UTC())
		}
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

func (a *Agent) dispatchCheck(ctx context.Context, item assignedMonitorSpec) {
	a.scheduleMu.Lock()
	state := a.schedule[item.ID]
	if state == nil || state.inFlight {
		a.scheduleMu.Unlock()
		return
	}
	select {
	case a.workerSem <- struct{}{}:
	default:
		a.scheduleMu.Unlock()
		a.logger.Warn("remote monitor check delayed: worker capacity exhausted", "monitor_id", item.ID)
		return
	}
	scheduledAt := state.nextDue
	state.inFlight = true
	state.nextDue = scheduledAt.Add(normalizedAssignedInterval(item))
	a.scheduleMu.Unlock()

	go func() {
		defer func() {
			<-a.workerSem
			a.scheduleMu.Lock()
			if state := a.schedule[item.ID]; state != nil {
				state.inFlight = false
			}
			a.scheduleMu.Unlock()
		}()
		result, ok := a.runCheck(ctx, item, scheduledAt)
		if !ok {
			return
		}
		if err := a.report(ctx, []reportResult{result}); err != nil {
			a.logger.Error("report failed", "monitor_id", item.ID, "error", err)
		}
	}()
}

func (a *Agent) runCheck(ctx context.Context, item assignedMonitorSpec, scheduledAt time.Time) (reportResult, bool) {
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
	kind := monitor.Kind(strings.TrimSpace(item.Kind))
	checker, ok := checkers[kind]
	if !ok {
		return reportResult{}, false
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
	res.CheckedAt = scheduledAt.UTC()
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
	return payload, true
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
