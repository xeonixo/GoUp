package httpserver

import (
	"errors"

	"goup/internal/netguard"
)

// validateIntegrationURL checks user supplied URLs of outbound integrations
// (Matrix homeserver, OIDC issuer): https only, no credentials, and no private
// or loopback targets unless GOUP_ALLOW_PRIVATE_INTEGRATIONS=true. Hostnames
// are additionally checked at connect time by the guarded HTTP clients.
func (s *Server) validateIntegrationURL(raw string) error {
	if _, err := netguard.ValidateURL(raw, s.cfg.AllowPrivateIntegrations); err != nil {
		if errors.Is(err, netguard.ErrBlockedAddress) {
			return errors.New("target address is not allowed (private/loopback/metadata addresses are blocked; set GOUP_ALLOW_PRIVATE_INTEGRATIONS=true to allow private networks)")
		}
		return err
	}
	return nil
}
