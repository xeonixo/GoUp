package monitor

import (
	"crypto/tls"
	"fmt"
	"time"
)

func applyTLSMetadata(result *Result, state tls.ConnectionState) {
	if len(state.PeerCertificates) == 0 {
		return
	}

	notAfter := state.PeerCertificates[0].NotAfter.UTC()
	daysRemaining := int(time.Until(notAfter).Hours() / 24)
	tlsValid := true
	result.TLSValid = &tlsValid
	result.TLSNotAfter = &notAfter
	result.TLSDaysRemaining = &daysRemaining
}

func finalizeTLSResult(result *Result, okMessage string) (Status, string) {
	if result.TLSDaysRemaining == nil {
		return StatusUp, okMessage
	}

	daysRemaining := *result.TLSDaysRemaining
	if daysRemaining < 0 {
		return StatusDown, fmt.Sprintf("certificate expired %d days ago", -daysRemaining)
	}
	if daysRemaining <= certificateWarningDays {
		return StatusDegraded, fmt.Sprintf("%s; certificate expires in %d days", okMessage, daysRemaining)
	}

	return StatusUp, okMessage
}
