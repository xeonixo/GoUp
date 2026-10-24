package auth

import "encoding/json"

const (
	oidcStateCookieName = "goup_oidc_state"
	oidcNonceCookieName = "goup_oidc_nonce"
)

type Identity struct {
	Subject string
	Email   string
	Name    string
	// EmailVerified is nil when the IdP did not send the email_verified claim.
	EmailVerified *bool
	// Groups holds the "groups" claim (if any).
	Groups []string
}

// flexStrings decodes a JSON string or array of strings; other shapes are ignored
// so an unexpected "groups" claim cannot break the login.
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(data []byte) error {
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*f = list
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*f = []string{single}
		return nil
	}
	*f = nil
	return nil
}
