package sqlite

import (
	"errors"
	"goup/internal/monitor"
	"strings"
	"time"
)

// Validation errors of maintenance windows; callers map them to localized messages.
var (
	ErrMaintenanceTitle   = errors.New("maintenance title is required (max 120 characters)")
	ErrMaintenanceText    = errors.New("maintenance description must not exceed 1000 characters")
	ErrMaintenanceTimes   = errors.New("maintenance start and end are required")
	ErrMaintenanceOrder   = errors.New("maintenance end must be after its start")
	ErrMaintenanceTooLong = errors.New("a recurring maintenance window must not be longer than its period")
	ErrMaintenanceTargets = errors.New("select at least one monitor or group")
	ErrMaintenanceInvalid = errors.New("invalid maintenance recurrence or scope")
)

// ValidateMaintenanceWindow checks a window before it is stored.
func ValidateMaintenanceWindow(w monitor.MaintenanceWindow) error {
	if strings.TrimSpace(w.Title) == "" || len([]rune(strings.TrimSpace(w.Title))) > 120 {
		return ErrMaintenanceTitle
	}
	if len([]rune(w.Description)) > 1000 {
		return ErrMaintenanceText
	}
	if w.StartsAt.IsZero() || w.EndsAt.IsZero() {
		return ErrMaintenanceTimes
	}
	if !w.EndsAt.After(w.StartsAt) {
		return ErrMaintenanceOrder
	}
	length := w.EndsAt.Sub(w.StartsAt)
	switch w.Recurrence {
	case monitor.RecurrenceNone:
	case monitor.RecurrenceDaily:
		if length > 24*time.Hour {
			return ErrMaintenanceTooLong
		}
	case monitor.RecurrenceWeekly:
		if length > 7*24*time.Hour {
			return ErrMaintenanceTooLong
		}
	default:
		return ErrMaintenanceInvalid
	}
	switch w.Scope {
	case monitor.MaintenanceScopeAll:
	case monitor.MaintenanceScopeMonitors:
		if len(w.MonitorIDs) == 0 {
			return ErrMaintenanceTargets
		}
	case monitor.MaintenanceScopeGroups:
		if len(w.Groups) == 0 {
			return ErrMaintenanceTargets
		}
	default:
		return ErrMaintenanceInvalid
	}
	return nil
}

func normalizeMaintenanceWindow(w monitor.MaintenanceWindow) monitor.MaintenanceWindow {
	w.Title = strings.TrimSpace(w.Title)
	w.Description = strings.TrimSpace(w.Description)
	w.StartsAt = w.StartsAt.UTC()
	w.EndsAt = w.EndsAt.UTC()
	w.Recurrence = monitor.NormalizeRecurrence(w.Recurrence)
	w.Scope = monitor.NormalizeMaintenanceScope(w.Scope)
	return w
}
