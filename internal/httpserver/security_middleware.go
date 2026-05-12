package httpserver

import "time"

type localLoginAttempt struct {
	Failures    int
	WindowStart time.Time
	LockedUntil time.Time
}

const (
	localLoginMaxFailures    = 5
	localLoginWindow         = 10 * time.Minute
	localLoginLockout        = 15 * time.Minute
	adminAccessMaxFailures   = 10
	adminAccessWindow        = 5 * time.Minute
	adminAccessLockout       = 30 * time.Minute
	bootstrapMaxFailures     = 8
	bootstrapWindow          = 5 * time.Minute
	bootstrapLockout         = 15 * time.Minute
	passwordResetTTL         = 15 * time.Minute
	controlPlaneAdminTTL     = 1 * time.Hour
	controlPlaneTOTPStageTTL = 5 * time.Minute
	controlPlaneCookie       = "goup_cp_admin"
	controlPlaneTOTPCookie   = "goup_cp_admin_totp"
)
