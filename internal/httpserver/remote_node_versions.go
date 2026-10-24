package httpserver

import (
	"context"
	"strconv"
	"strings"
	"time"

	"goup/internal/version"
)

const (
	remoteNodeVersionCurrent  = "current"
	remoteNodeVersionOutdated = "outdated"
	remoteNodeVersionUnknown  = "unknown"
)

// remoteNodeVersionSummaryResult counts enabled remote nodes; Outdated is a
// subset of Total.
type remoteNodeVersionSummaryResult struct {
	Total    int
	Online   int
	Offline  int
	Outdated int
}

// remoteNodeVersionState compares the node's reported version with the server
// build. Only vX.Y.Z style versions are ordered; anything else that differs
// (including a "dev" server) is "unknown" rather than "outdated".
func remoteNodeVersionState(nodeVersion, serverVersion string) string {
	nodeVersion = strings.TrimSpace(nodeVersion)
	serverVersion = strings.TrimSpace(serverVersion)
	if nodeVersion == "" {
		return remoteNodeVersionUnknown
	}
	if nodeVersion == serverVersion {
		return remoteNodeVersionCurrent
	}
	nodeParts, nodeOK := parseSemverCore(nodeVersion)
	serverParts, serverOK := parseSemverCore(serverVersion)
	if !nodeOK || !serverOK {
		return remoteNodeVersionUnknown
	}
	for i := range nodeParts {
		if nodeParts[i] < serverParts[i] {
			return remoteNodeVersionOutdated
		}
		if nodeParts[i] > serverParts[i] {
			return remoteNodeVersionCurrent
		}
	}
	return remoteNodeVersionCurrent
}

// parseSemverCore parses "v1.2.3" or "1.2.3" (ignoring -prerelease/+build).
func parseSemverCore(raw string) ([3]int, bool) {
	var parts [3]int
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if cut := strings.IndexAny(raw, "-+"); cut >= 0 {
		raw = raw[:cut]
	}
	fields := strings.Split(raw, ".")
	if len(fields) != 3 {
		return parts, false
	}
	for i, field := range fields {
		value, err := strconv.Atoi(field)
		if err != nil || value < 0 {
			return parts, false
		}
		parts[i] = value
	}
	return parts, true
}

// remoteNodeVersionSummary counts enabled remote nodes for one tenant, or for
// all tenants when tenantID <= 0.
func (s *Server) remoteNodeVersionSummary(ctx context.Context, tenantID int64) (remoteNodeVersionSummaryResult, error) {
	var summary remoteNodeVersionSummaryResult
	nodes, err := s.controlStore.ListAllEnabledRemoteNodes(ctx)
	if err != nil {
		return summary, err
	}
	now := time.Now().UTC()
	for _, node := range nodes {
		if tenantID > 0 && node.TenantID != tenantID {
			continue
		}
		summary.Total++
		if node.IsOnline(now) {
			summary.Online++
		} else {
			summary.Offline++
		}
		if remoteNodeVersionState(node.AgentVersion, version.Version) == remoteNodeVersionOutdated {
			summary.Outdated++
		}
	}
	return summary, nil
}
