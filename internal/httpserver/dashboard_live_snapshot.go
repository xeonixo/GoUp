package httpserver

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func hashDashboardFragment(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func parseDashboardLiveRequestedParts(raw string) map[string]struct{} {
	if raw == "" {
		return nil
	}
	allowed := map[string]struct{}{
		"stats":               {},
		"board":               {},
		"state_events":        {},
		"notification_events": {},
		"group_options":       {},
	}
	parts := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		part := strings.TrimSpace(strings.ToLower(item))
		if part == "" {
			continue
		}
		if _, ok := allowed[part]; ok {
			parts[part] = struct{}{}
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return parts
}

func parseDashboardLiveRequestedBoardGroups(raw string) []string {
	if raw == "" {
		return nil
	}
	groups := make([]string, 0, 8)
	seen := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		group := strings.TrimSpace(item)
		if group == "" {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		groups = append(groups, group)
		if len(groups) >= 64 {
			break
		}
	}
	if len(groups) == 0 {
		return nil
	}
	return groups
}

func hasDashboardLivePart(parts map[string]struct{}, part string) bool {
	_, ok := parts[part]
	return ok
}

func filterDashboardLiveSnapshotParts(snapshot dashboardLiveSnapshotResponse, parts map[string]struct{}) dashboardLiveSnapshotResponse {
	if _, ok := parts["stats"]; !ok {
		snapshot.StatsHTML = ""
		snapshot.StatsHash = ""
	}
	if _, ok := parts["board"]; !ok {
		snapshot.BoardHTML = ""
		snapshot.BoardHash = ""
		snapshot.BoardGroupsHTML = nil
		snapshot.BoardGroupsHash = nil
	}
	if _, ok := parts["state_events"]; !ok {
		snapshot.StateEventsHTML = ""
		snapshot.StateEventsHash = ""
	}
	if _, ok := parts["notification_events"]; !ok {
		snapshot.NotificationEventsHTML = ""
		snapshot.NotificationEventsHash = ""
	}
	if _, ok := parts["group_options"]; !ok {
		snapshot.GroupOptionsHTML = ""
		snapshot.GroupOptionsHash = ""
	}
	return snapshot
}

func filterDashboardLiveSnapshotBoardGroups(snapshot dashboardLiveSnapshotResponse, groups []string) dashboardLiveSnapshotResponse {
	if len(groups) == 0 {
		return snapshot
	}
	if len(snapshot.BoardGroupsHTML) == 0 {
		return snapshot
	}

	filteredHTML := make(map[string]string)
	filteredHashes := make(map[string]string)
	for _, group := range groups {
		fragment, ok := snapshot.BoardGroupsHTML[group]
		if !ok {
			continue
		}
		filteredHTML[group] = fragment
		hash := snapshot.BoardGroupsHash[group]
		if hash == "" {
			hash = hashDashboardFragment(fragment)
		}
		filteredHashes[group] = hash
	}

	snapshot.BoardHTML = ""
	snapshot.BoardGroupsHTML = filteredHTML
	snapshot.BoardGroupsHash = filteredHashes
	return snapshot
}

func dashboardLiveChangedParts(previous dashboardLiveSnapshotResponse, next dashboardLiveSnapshotResponse) []string {
	parts := make([]string, 0, 5)
	if previous.StatsHash != next.StatsHash {
		parts = append(parts, "stats")
	}
	if previous.BoardHash != next.BoardHash {
		parts = append(parts, "board")
	}
	if previous.StateEventsHash != next.StateEventsHash {
		parts = append(parts, "state_events")
	}
	if previous.NotificationEventsHash != next.NotificationEventsHash {
		parts = append(parts, "notification_events")
	}
	if previous.GroupOptionsHash != next.GroupOptionsHash {
		parts = append(parts, "group_options")
	}
	return parts
}

func dashboardLiveChangedBoardGroups(previous dashboardLiveSnapshotResponse, next dashboardLiveSnapshotResponse) []string {
	if len(previous.BoardGroupOrder) == 0 || len(next.BoardGroupOrder) == 0 {
		return nil
	}
	if !equalStringSlices(previous.BoardGroupOrder, next.BoardGroupOrder) {
		return nil
	}
	if len(previous.BoardGroupHashes) != len(next.BoardGroupHashes) {
		return nil
	}

	changed := make([]string, 0, len(next.BoardGroupOrder))
	for _, group := range next.BoardGroupOrder {
		nextHash, nextOK := next.BoardGroupHashes[group]
		prevHash, prevOK := previous.BoardGroupHashes[group]
		if !nextOK || !prevOK {
			return nil
		}
		if nextHash != prevHash {
			changed = append(changed, group)
		}
	}

	if len(changed) == 0 {
		return nil
	}
	return changed
}

func equalStringSlices(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
