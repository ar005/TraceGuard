// internal/sso/identity.go — shared types for SSO identity resolution.

package sso

// Identity carries normalized user attributes extracted from a SAML assertion or OIDC token.
type Identity struct {
	// Subject is the stable IdP-issued identifier (SAML NameID or OIDC sub).
	Subject string

	// Email is the user's email address from the IdP.
	Email string

	// Name is the user's display name.
	Name string

	// Role is the TraceGuard role mapped from an IdP attribute/claim.
	// Empty string means "use the SSO config's default_role".
	Role string
}
