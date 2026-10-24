package monitor

import (
	"sync"
	"time"
)

const (
	runnerStatsWindow    = 5 * time.Minute
	runnerStatsMaxEvents = 50000
)

// runnerStats collects lightweight scheduler counters. The zero value is ready to use and all
// methods are safe for concurrent use.
type runnerStats struct {
	mu           sync.Mutex
	started      uint64
	running      int
	backlog      int
	lastLoop     time.Duration
	lastLoopAt   time.Time
	completed    []completedCheck
	completedSum time.Duration
}

type completedCheck struct {
	at       time.Time
	duration time.Duration
}

// RunnerStatsSnapshot is a point-in-time view of the runner's scheduler state.
type RunnerStatsSnapshot struct {
	Workers int
	// ScheduledMonitors is the number of enabled local monitors the scheduler tracks.
	ScheduledMonitors int
	// ChecksLast5Min counts checks that finished within the last five minutes.
	ChecksLast5Min int
	// AvgCheckDuration is the mean duration of those checks (zero when none ran).
	AvgCheckDuration time.Duration
	// Running is the number of checks currently executing.
	Running int
	// Backlog is the number of checks that were due in the last loop but could not be started.
	Backlog int
	// LastLoopDuration is how long the most recent scheduling loop took.
	LastLoopDuration time.Duration
	LastLoopAt       time.Time
}

func (s *runnerStats) checkStarted() {
	s.mu.Lock()
	s.started++
	s.running++
	s.mu.Unlock()
}

func (s *runnerStats) checkFinished(now time.Time, duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running > 0 {
		s.running--
	}
	s.pruneLocked(now)
	if len(s.completed) >= runnerStatsMaxEvents {
		s.completedSum -= s.completed[0].duration
		s.completed = s.completed[1:]
	}
	s.completed = append(s.completed, completedCheck{at: now, duration: duration})
	s.completedSum += duration
}

func (s *runnerStats) startedTotal() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

func (s *runnerStats) setBacklog(n int) {
	if n < 0 {
		n = 0
	}
	s.mu.Lock()
	s.backlog = n
	s.mu.Unlock()
}

func (s *runnerStats) recordLoop(now time.Time, duration time.Duration) {
	s.mu.Lock()
	s.lastLoop = duration
	s.lastLoopAt = now
	s.mu.Unlock()
}

// pruneLocked drops completions older than the stats window.
func (s *runnerStats) pruneLocked(now time.Time) {
	cutoff := now.Add(-runnerStatsWindow)
	drop := 0
	for drop < len(s.completed) && s.completed[drop].at.Before(cutoff) {
		s.completedSum -= s.completed[drop].duration
		drop++
	}
	if drop > 0 {
		s.completed = append([]completedCheck(nil), s.completed[drop:]...)
	}
}

func (s *runnerStats) snapshot(now time.Time) RunnerStatsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	snap := RunnerStatsSnapshot{
		ChecksLast5Min:   len(s.completed),
		Running:          s.running,
		Backlog:          s.backlog,
		LastLoopDuration: s.lastLoop,
		LastLoopAt:       s.lastLoopAt,
	}
	if len(s.completed) > 0 {
		snap.AvgCheckDuration = s.completedSum / time.Duration(len(s.completed))
	}
	return snap
}

// Stats returns a concurrency-safe snapshot of scheduler counters.
func (r *Runner) Stats() RunnerStatsSnapshot {
	snap := r.stats.snapshot(time.Now())
	r.scheduleMu.Lock()
	snap.Workers = r.workers
	snap.ScheduledMonitors = len(r.schedule)
	r.scheduleMu.Unlock()
	return snap
}
