// internal/api/sso_handlers.go — SSO/SAML/OIDC HTTP handlers.
//
// Public routes (no auth required — called by IdP or browser):
//   POST /api/v1/sso/lookup             — email → SSO discovery
//   GET  /api/v1/sso/saml/metadata      — SP metadata XML for IdP setup
//   GET  /api/v1/sso/saml/login         — initiate SAML redirect-binding flow
//   POST /api/v1/sso/saml/acs           — SAML Assertion Consumer Service
//   GET  /api/v1/sso/oidc/login         — initiate OIDC authorization code flow
//   GET  /api/v1/sso/oidc/callback      — OIDC callback
//
// Admin routes (authMiddleware + adminOnly):
//   GET    /api/v1/sso/configs           — list tenant SSO configs
//   POST   /api/v1/sso/configs           — create SSO config
//   GET    /api/v1/sso/configs/:id       — get SSO config (secrets redacted)
//   PUT    /api/v1/sso/configs/:id       — update SSO config
//   DELETE /api/v1/sso/configs/:id       — delete SSO config

package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/youredr/edr-backend/internal/sso"
	"github.com/youredr/edr-backend/internal/store"
	"github.com/youredr/edr-backend/internal/users"
)

// ─── OIDC state (in-memory, TTL 10 min) ──────────────────────────────────────

type oidcStateEntry struct {
	tenantID  string
	expiresAt time.Time
}

var (
	oidcStateMu sync.Mutex
	oidcStates  = map[string]oidcStateEntry{}
)

func storeOIDCState(tenantID string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	state := hex.EncodeToString(b)
	oidcStateMu.Lock()
	now := time.Now()
	for k, v := range oidcStates {
		if v.expiresAt.Before(now) {
			delete(oidcStates, k)
		}
	}
	oidcStates[state] = oidcStateEntry{tenantID: tenantID, expiresAt: now.Add(10 * time.Minute)}
	oidcStateMu.Unlock()
	return state
}

func consumeOIDCState(state string) (string, bool) {
	oidcStateMu.Lock()
	defer oidcStateMu.Unlock()
	e, ok := oidcStates[state]
	if !ok || e.expiresAt.Before(time.Now()) {
		delete(oidcStates, state)
		return "", false
	}
	delete(oidcStates, state)
	return e.tenantID, true
}

// ─── SAML request-ID store (in-memory, TTL 5 min) ────────────────────────────

var (
	samlReqMu    sync.Mutex
	samlRequests = map[string]time.Time{}
)

func storeSAMLRequestID(id string) {
	samlReqMu.Lock()
	now := time.Now()
	for k, exp := range samlRequests {
		if exp.Before(now) {
			delete(samlRequests, k)
		}
	}
	samlRequests[id] = now.Add(5 * time.Minute)
	samlReqMu.Unlock()
}

func liveSAMLRequestIDs() []string {
	samlReqMu.Lock()
	defer samlReqMu.Unlock()
	now := time.Now()
	ids := make([]string, 0, len(samlRequests))
	for k, exp := range samlRequests {
		if exp.After(now) {
			ids = append(ids, k)
		}
	}
	return ids
}

// ─── Discovery ────────────────────────────────────────────────────────────────

// handleSSOLookup accepts an email address and returns whether SSO is configured
// for that email domain, so the login page can show the "Sign in with SSO" button.
//
//	POST /api/v1/sso/lookup   {"email":"user@corp.example.com"}
func (s *Server) handleSSOLookup(c *gin.Context) {
	var body struct {
		Email string `json:"email" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email is required"})
		return
	}
	parts := strings.SplitN(body.Email, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		c.JSON(http.StatusOK, gin.H{"sso_enabled": false})
		return
	}
	domain := strings.ToLower(parts[1])

	cfg, err := s.store.GetEnabledSSOConfigByDomain(c.Request.Context(), domain)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"sso_enabled": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"sso_enabled":   true,
		"provider_type": cfg.ProviderType,
		"provider_name": cfg.ProviderName,
		"tenant_id":     cfg.TenantID,
	})
}

// ─── SAML endpoints ───────────────────────────────────────────────────────────

// handleSAMLMetadata returns the SP metadata XML for the IdP administrator.
//
//	GET /api/v1/sso/saml/metadata?tenant_id=xxx
func (s *Server) handleSAMLMetadata(c *gin.Context) {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return
	}
	cfg, err := s.store.GetEnabledSSOConfig(c.Request.Context(), tenantID, "saml")
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no SAML config for tenant"})
		return
	}
	sp, err := sso.NewSAMLProvider(
		cfg.SAMLIdPMetadataXML, cfg.SAMLSPKeyPEM, cfg.SAMLSPCertPEM,
		s.publicBaseURL, cfg.SAMLAttributeEmail, cfg.SAMLAttributeName, cfg.SAMLAttributeRole,
	)
	if err != nil {
		s.log.Error().Err(err).Msg("saml metadata: build SP")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SAML configuration error"})
		return
	}
	xmlBytes, err := sp.MetadataXML()
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.Data(http.StatusOK, "application/xml; charset=utf-8", xmlBytes)
}

// handleSAMLLogin initiates the SAML redirect-binding flow.
//
//	GET /api/v1/sso/saml/login?tenant_id=xxx
func (s *Server) handleSAMLLogin(c *gin.Context) {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return
	}
	cfg, err := s.store.GetEnabledSSOConfig(c.Request.Context(), tenantID, "saml")
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no SAML config for tenant"})
		return
	}
	sp, err := sso.NewSAMLProvider(
		cfg.SAMLIdPMetadataXML, cfg.SAMLSPKeyPEM, cfg.SAMLSPCertPEM,
		s.publicBaseURL, cfg.SAMLAttributeEmail, cfg.SAMLAttributeName, cfg.SAMLAttributeRole,
	)
	if err != nil {
		s.log.Error().Err(err).Msg("saml login: build SP")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SAML configuration error"})
		return
	}
	redirectURL, requestID, err := sp.InitiateLogin(tenantID)
	if err != nil {
		s.log.Error().Err(err).Msg("saml login: initiate")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SAML login failed"})
		return
	}
	storeSAMLRequestID(requestID)
	c.Redirect(http.StatusFound, redirectURL)
}

// handleSAMLACS processes the SAMLResponse posted by the IdP (Assertion Consumer Service).
//
//	POST /api/v1/sso/saml/acs
func (s *Server) handleSAMLACS(c *gin.Context) {
	tenantID := c.PostForm("RelayState")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing RelayState"})
		return
	}
	cfg, err := s.store.GetEnabledSSOConfig(c.Request.Context(), tenantID, "saml")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown tenant"})
		return
	}
	sp, err := sso.NewSAMLProvider(
		cfg.SAMLIdPMetadataXML, cfg.SAMLSPKeyPEM, cfg.SAMLSPCertPEM,
		s.publicBaseURL, cfg.SAMLAttributeEmail, cfg.SAMLAttributeName, cfg.SAMLAttributeRole,
	)
	if err != nil {
		s.log.Error().Err(err).Msg("saml acs: build SP")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SAML configuration error"})
		return
	}
	identity, err := sp.ParseAssertion(c.Request, liveSAMLRequestIDs())
	if err != nil {
		s.log.Warn().Err(err).Str("tenant_id", tenantID).Msg("saml acs: invalid assertion")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "SAML assertion validation failed"})
		return
	}
	s.finishSSOLogin(c, cfg, identity)
}

// ─── OIDC endpoints ───────────────────────────────────────────────────────────

// handleOIDCLogin initiates the OIDC authorization code flow.
//
//	GET /api/v1/sso/oidc/login?tenant_id=xxx
func (s *Server) handleOIDCLogin(c *gin.Context) {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return
	}
	cfg, err := s.store.GetEnabledSSOConfig(c.Request.Context(), tenantID, "oidc")
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no OIDC config for tenant"})
		return
	}
	op, err := sso.NewOIDCProvider(
		c.Request.Context(),
		cfg.OIDCIssuerURL, cfg.OIDCClientID, cfg.OIDCClientSecret,
		s.publicBaseURL, cfg.OIDCClaimEmail, cfg.OIDCClaimName, cfg.OIDCClaimRole,
	)
	if err != nil {
		s.log.Error().Err(err).Msg("oidc login: build provider")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OIDC configuration error"})
		return
	}
	state := storeOIDCState(tenantID)
	c.Redirect(http.StatusFound, op.AuthURL(state))
}

// handleOIDCCallback handles the IdP redirect back after user authentication.
//
//	GET /api/v1/sso/oidc/callback?code=xxx&state=xxx
func (s *Server) handleOIDCCallback(c *gin.Context) {
	tenantID, ok := consumeOIDCState(c.Query("state"))
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired state"})
		return
	}
	cfg, err := s.store.GetEnabledSSOConfig(c.Request.Context(), tenantID, "oidc")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown tenant"})
		return
	}
	op, err := sso.NewOIDCProvider(
		c.Request.Context(),
		cfg.OIDCIssuerURL, cfg.OIDCClientID, cfg.OIDCClientSecret,
		s.publicBaseURL, cfg.OIDCClaimEmail, cfg.OIDCClaimName, cfg.OIDCClaimRole,
	)
	if err != nil {
		s.log.Error().Err(err).Msg("oidc callback: build provider")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OIDC configuration error"})
		return
	}
	identity, err := op.Exchange(c.Request.Context(), c.Query("code"))
	if err != nil {
		s.log.Warn().Err(err).Str("tenant_id", tenantID).Msg("oidc callback: exchange failed")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OIDC authentication failed"})
		return
	}
	s.finishSSOLogin(c, cfg, identity)
}

// ─── Shared SSO login completion ─────────────────────────────────────────────

// finishSSOLogin provisions/finds the user, issues a JWT cookie, and redirects to "/".
func (s *Server) finishSSOLogin(c *gin.Context, cfg *store.SSOConfig, identity *sso.Identity) {
	ctx := c.Request.Context()

	role := identity.Role
	if role == "" {
		role = cfg.DefaultRole
	}

	var u *users.User
	var err error

	if !cfg.AutoProvision {
		u, err = s.um.GetBySSOSubject(ctx, cfg.ID, identity.Subject, cfg.TenantID)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "user not provisioned for SSO"})
			return
		}
	} else {
		u, _, err = s.um.ProvisionSSOUser(ctx,
			cfg.TenantID, cfg.ID, identity.Subject, identity.Email, identity.Name, role)
		if err != nil {
			s.log.Error().Err(err).Str("email", identity.Email).Msg("sso: provision user")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user provisioning failed"})
			return
		}
	}

	if !u.Enabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "account disabled"})
		return
	}

	token, err := s.um.IssueToken(u)
	if err != nil {
		s.jsonError(c, err)
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "auth",
		Value:    token,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
	c.Redirect(http.StatusFound, "/")
}

// ─── Admin CRUD for SSO configs ───────────────────────────────────────────────

// handleListSSOConfigs lists all SSO configs for the caller's tenant.
//
//	GET /api/v1/sso/configs
func (s *Server) handleListSSOConfigs(c *gin.Context) {
	tid := c.GetString("tenant_id")
	cfgs, err := s.store.ListSSOConfigs(c.Request.Context(), tid)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	type safeConfig struct {
		ID            string         `json:"id"`
		TenantID      string         `json:"tenant_id"`
		ProviderName  string         `json:"provider_name"`
		ProviderType  string         `json:"provider_type"`
		Enabled       bool           `json:"enabled"`
		AutoProvision bool           `json:"auto_provision"`
		DefaultRole   string         `json:"default_role"`
		Domains       pq.StringArray `json:"domains"`
		SAMLSPCertPEM string         `json:"saml_sp_cert_pem,omitempty"`
		OIDCIssuerURL string         `json:"oidc_issuer_url,omitempty"`
		OIDCClientID  string         `json:"oidc_client_id,omitempty"`
		CreatedAt     time.Time      `json:"created_at"`
		UpdatedAt     time.Time      `json:"updated_at"`
	}
	out := make([]safeConfig, len(cfgs))
	for i, cfg := range cfgs {
		out[i] = safeConfig{
			ID: cfg.ID, TenantID: cfg.TenantID,
			ProviderName: cfg.ProviderName, ProviderType: cfg.ProviderType,
			Enabled: cfg.Enabled, AutoProvision: cfg.AutoProvision,
			DefaultRole: cfg.DefaultRole, Domains: cfg.Domains,
			SAMLSPCertPEM: cfg.SAMLSPCertPEM,
			OIDCIssuerURL: cfg.OIDCIssuerURL, OIDCClientID: cfg.OIDCClientID,
			CreatedAt: cfg.CreatedAt, UpdatedAt: cfg.UpdatedAt,
		}
	}
	c.JSON(http.StatusOK, out)
}

// handleCreateSSOConfig creates a new SSO configuration.
//
//	POST /api/v1/sso/configs
func (s *Server) handleCreateSSOConfig(c *gin.Context) {
	tid := c.GetString("tenant_id")

	var body struct {
		ProviderName  string   `json:"provider_name"  binding:"required"`
		ProviderType  string   `json:"provider_type"  binding:"required"`
		Enabled       *bool    `json:"enabled"`
		AutoProvision *bool    `json:"auto_provision"`
		DefaultRole   string   `json:"default_role"`
		Domains       []string `json:"domains"`

		SAMLIdPMetadataXML string `json:"saml_idp_metadata_xml"`
		SAMLAttributeEmail string `json:"saml_attribute_email"`
		SAMLAttributeName  string `json:"saml_attribute_name"`
		SAMLAttributeRole  string `json:"saml_attribute_role"`

		OIDCIssuerURL    string `json:"oidc_issuer_url"`
		OIDCClientID     string `json:"oidc_client_id"`
		OIDCClientSecret string `json:"oidc_client_secret"`
		OIDCClaimEmail   string `json:"oidc_claim_email"`
		OIDCClaimName    string `json:"oidc_claim_name"`
		OIDCClaimRole    string `json:"oidc_claim_role"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.ProviderType != "saml" && body.ProviderType != "oidc" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider_type must be 'saml' or 'oidc'"})
		return
	}
	if body.ProviderType == "saml" && body.SAMLIdPMetadataXML == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "saml_idp_metadata_xml is required for SAML"})
		return
	}
	if body.ProviderType == "oidc" && (body.OIDCIssuerURL == "" || body.OIDCClientID == "" || body.OIDCClientSecret == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "oidc_issuer_url, oidc_client_id, and oidc_client_secret are required for OIDC"})
		return
	}

	cfg := &store.SSOConfig{
		ID:           uuid.New().String(),
		TenantID:     tid,
		ProviderName: body.ProviderName,
		ProviderType: body.ProviderType,
		Enabled:      true, AutoProvision: true, DefaultRole: "analyst",
		Domains:            pq.StringArray(body.Domains),
		SAMLIdPMetadataXML: body.SAMLIdPMetadataXML,
		SAMLAttributeEmail: body.SAMLAttributeEmail,
		SAMLAttributeName:  body.SAMLAttributeName,
		SAMLAttributeRole:  body.SAMLAttributeRole,
		OIDCIssuerURL:      body.OIDCIssuerURL,
		OIDCClientID:       body.OIDCClientID,
		OIDCClientSecret:   body.OIDCClientSecret,
		OIDCClaimEmail:     body.OIDCClaimEmail,
		OIDCClaimName:      body.OIDCClaimName,
		OIDCClaimRole:      body.OIDCClaimRole,
	}
	if body.Enabled != nil {
		cfg.Enabled = *body.Enabled
	}
	if body.AutoProvision != nil {
		cfg.AutoProvision = *body.AutoProvision
	}
	if body.DefaultRole != "" {
		cfg.DefaultRole = body.DefaultRole
	}

	// Generate SP key pair for SAML — stored server-side, cert given to IdP admin.
	if body.ProviderType == "saml" {
		keyPEM, certPEM, err := sso.GenerateSPKeyPair()
		if err != nil {
			s.jsonError(c, err)
			return
		}
		cfg.SAMLSPKeyPEM = keyPEM
		cfg.SAMLSPCertPEM = certPEM
	}

	if err := s.store.CreateSSOConfig(c.Request.Context(), cfg); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"id":                cfg.ID,
		"saml_sp_cert_pem":  cfg.SAMLSPCertPEM,
		"saml_metadata_url": s.publicBaseURL + "/api/v1/sso/saml/metadata?tenant_id=" + tid,
		"oidc_redirect_uri": s.publicBaseURL + "/api/v1/sso/oidc/callback",
	})
}

// handleGetSSOConfig returns one SSO config with secrets redacted.
//
//	GET /api/v1/sso/configs/:id
func (s *Server) handleGetSSOConfig(c *gin.Context) {
	tid := c.GetString("tenant_id")
	cfg, err := s.store.GetSSOConfig(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		s.jsonError(c, err)
		return
	}
	cfg.SAMLSPKeyPEM = ""     // never expose the private key
	cfg.OIDCClientSecret = "" // never expose client secret
	c.JSON(http.StatusOK, cfg)
}

// handleUpdateSSOConfig updates an existing SSO config.
//
//	PUT /api/v1/sso/configs/:id
func (s *Server) handleUpdateSSOConfig(c *gin.Context) {
	tid := c.GetString("tenant_id")
	ctx := c.Request.Context()

	existing, err := s.store.GetSSOConfig(ctx, c.Param("id"), tid)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		s.jsonError(c, err)
		return
	}

	var body struct {
		ProviderName  string   `json:"provider_name"`
		Enabled       *bool    `json:"enabled"`
		AutoProvision *bool    `json:"auto_provision"`
		DefaultRole   string   `json:"default_role"`
		Domains       []string `json:"domains"`

		SAMLIdPMetadataXML string `json:"saml_idp_metadata_xml"`
		SAMLAttributeEmail string `json:"saml_attribute_email"`
		SAMLAttributeName  string `json:"saml_attribute_name"`
		SAMLAttributeRole  string `json:"saml_attribute_role"`

		OIDCIssuerURL    string `json:"oidc_issuer_url"`
		OIDCClientID     string `json:"oidc_client_id"`
		OIDCClientSecret string `json:"oidc_client_secret"`
		OIDCClaimEmail   string `json:"oidc_claim_email"`
		OIDCClaimName    string `json:"oidc_claim_name"`
		OIDCClaimRole    string `json:"oidc_claim_role"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if body.ProviderName != "" {
		existing.ProviderName = body.ProviderName
	}
	if body.Enabled != nil {
		existing.Enabled = *body.Enabled
	}
	if body.AutoProvision != nil {
		existing.AutoProvision = *body.AutoProvision
	}
	if body.DefaultRole != "" {
		existing.DefaultRole = body.DefaultRole
	}
	if body.Domains != nil {
		existing.Domains = pq.StringArray(body.Domains)
	}
	if body.SAMLIdPMetadataXML != "" {
		existing.SAMLIdPMetadataXML = body.SAMLIdPMetadataXML
	}
	if body.SAMLAttributeEmail != "" {
		existing.SAMLAttributeEmail = body.SAMLAttributeEmail
	}
	if body.SAMLAttributeName != "" {
		existing.SAMLAttributeName = body.SAMLAttributeName
	}
	if body.SAMLAttributeRole != "" {
		existing.SAMLAttributeRole = body.SAMLAttributeRole
	}
	if body.OIDCIssuerURL != "" {
		existing.OIDCIssuerURL = body.OIDCIssuerURL
	}
	if body.OIDCClientID != "" {
		existing.OIDCClientID = body.OIDCClientID
	}
	if body.OIDCClientSecret != "" {
		existing.OIDCClientSecret = body.OIDCClientSecret
	}
	if body.OIDCClaimEmail != "" {
		existing.OIDCClaimEmail = body.OIDCClaimEmail
	}
	if body.OIDCClaimName != "" {
		existing.OIDCClaimName = body.OIDCClaimName
	}
	if body.OIDCClaimRole != "" {
		existing.OIDCClaimRole = body.OIDCClaimRole
	}

	if err := s.store.UpdateSSOConfig(ctx, existing); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// handleDeleteSSOConfig removes an SSO config.
//
//	DELETE /api/v1/sso/configs/:id
func (s *Server) handleDeleteSSOConfig(c *gin.Context) {
	tid := c.GetString("tenant_id")
	if err := s.store.DeleteSSOConfig(c.Request.Context(), c.Param("id"), tid); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
