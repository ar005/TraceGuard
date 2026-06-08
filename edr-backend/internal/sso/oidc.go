// internal/sso/oidc.go — OIDC / OAuth2 Service Provider.

package sso

import (
	"context"
	"fmt"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider wraps an OIDC discovery configuration for one tenant.
type OIDCProvider struct {
	provider   *gooidc.Provider
	verifier   *gooidc.IDTokenVerifier
	oauth2Cfg  oauth2.Config
	emailClaim string
	nameClaim  string
	roleClaim  string
}

// NewOIDCProvider creates an OIDCProvider by discovering the IdP's endpoints.
// baseURL is the TraceGuard backend public base URL (for the redirect URI).
func NewOIDCProvider(
	ctx context.Context,
	issuerURL, clientID, clientSecret string,
	baseURL, emailClaim, nameClaim, roleClaim string,
) (*OIDCProvider, error) {
	if emailClaim == "" {
		emailClaim = "email"
	}
	if nameClaim == "" {
		nameClaim = "preferred_username"
	}

	provider, err := gooidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover provider %q: %w", issuerURL, err)
	}

	verifier := provider.Verifier(&gooidc.Config{ClientID: clientID})

	oauth2Cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  baseURL + "/api/v1/sso/oidc/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{gooidc.ScopeOpenID, "email", "profile"},
	}

	return &OIDCProvider{
		provider:   provider,
		verifier:   verifier,
		oauth2Cfg:  oauth2Cfg,
		emailClaim: emailClaim,
		nameClaim:  nameClaim,
		roleClaim:  roleClaim,
	}, nil
}

// AuthURL builds the IdP authorization URL.
// state should be a random CSRF token tied to the user's session.
func (p *OIDCProvider) AuthURL(state string) string {
	return p.oauth2Cfg.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// Exchange trades an authorization code for an ID token and returns the Identity.
func (p *OIDCProvider) Exchange(ctx context.Context, code string) (*Identity, error) {
	token, err := p.oauth2Cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oidc: code exchange: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("oidc: no id_token in token response")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: verify id_token: %w", err)
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: extract claims: %w", err)
	}

	id := &Identity{
		Subject: idToken.Subject,
	}

	if v, ok := claims[p.emailClaim].(string); ok {
		id.Email = v
	}
	if v, ok := claims[p.nameClaim].(string); ok {
		id.Name = v
	}
	if p.roleClaim != "" {
		if v, ok := claims[p.roleClaim].(string); ok {
			id.Role = v
		}
	}

	if id.Email == "" {
		id.Email = idToken.Subject
	}

	return id, nil
}
