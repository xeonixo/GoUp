package remotenode

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"goup/internal/monitor"
)

func TestUpdateAssignmentsSeedsCascadedDueFromInterval(t *testing.T) {
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	agent := New(Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assigned := []assignedMonitorSpec{
		{ID: 42, IntervalSeconds: 60, TimeoutSeconds: 5, Kind: string(monitor.KindHTTPS)},
	}

	agent.updateAssignments(assigned, now)

	state := agent.schedule[42]
	if state == nil {
		t.Fatalf("expected schedule state")
	}
	want := monitor.CascadedDueAtOrAfter(42, time.Minute, now)
	if !state.nextDue.Equal(want) {
		t.Fatalf("nextDue = %s, want %s", state.nextDue, want)
	}
}

func TestDueAssignmentsUsesPerMonitorInterval(t *testing.T) {
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	agent := New(Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	agent.assignments[1] = assignedMonitorSpec{ID: 1, IntervalSeconds: 60}
	agent.schedule[1] = &remoteScheduleState{nextDue: now}

	due := agent.dueAssignments(now)
	if len(due) != 1 {
		t.Fatalf("got %d due assignments, want 1", len(due))
	}
	if got := normalizedAssignedInterval(due[0]); got != time.Minute {
		t.Fatalf("interval = %s, want 1m", got)
	}
}
