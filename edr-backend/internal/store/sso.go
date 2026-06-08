// internal/store/sso.go — SSO configuration persistence.

package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/lib/pq"
)

// SSOConfig holds one SSO provider configuration for a tenant.
type SSOConfig struct {
	ID            string    `db:"id"`
	TenantID      string    `db:"tenant_id"`
	ProviderName  string    `db:"provider_name"`
	ProviderType  string    `db:"provider_type"` // "saml" | "oidc"
	Enabled       bool      `db:"enabled"`
	AutoProvision bool      `db:"auto_provision"`
	DefaultRole   string    `db:"default_role"`
	Domains       pq.StringArray `db:"domains"` // email domains this config handles

	// SAML
	SAMLIdPMetadataXML string `db:"saml_idp_metadata_xml"`
	SAMLSPKeyPEM       string `db:"saml_sp_key_pem"`
	SAMLSPCertPEM      string `db:"saml_sp_cert_pem"`
	SAMLAttributeEmail string `db:"saml_attribute_email"`
	SAMLAttributeName  string `db:"saml_attribute_name"`
	SAMLAttributeRole  string `db:"saml_attribute_role"`

	// OIDC
	OIDCIssuerURL    string `db:"oidc_issuer_url"`
	OIDCClientID     string `db:"oidc_client_id"`
	OIDCClientSecret string `db:"oidc_client_secret"`
	OIDCClaimEmail   string `db:"oidc_claim_email"`
	OIDCClaimName    string `db:"oidc_claim_name"`
	OIDCClaimRole    string `db:"oidc_claim_role"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

const ssoSelectAll = `
SELECT id, tenant_id, provider_name, provider_type, enabled, auto_provision,
       default_role, domains,
       saml_idp_metadata_xml, saml_sp_key_pem, saml_sp_cert_pem,
       saml_attribute_email, saml_attribute_name, saml_attribute_role,
       oidc_issuer_url, oidc_client_id, oidc_client_secret,
       oidc_claim_email, oidc_claim_name, oidc_claim_role,
       created_at, updated_at
FROM sso_configs`

func (s *Store) CreateSSOConfig(ctx context.Context, cfg *SSOConfig) error {
	_, err := s.db.NamedExecContext(ctx, `
		INSERT INTO sso_configs (
			id, tenant_id, provider_name, provider_type, enabled, auto_provision,
			default_role, domains,
			saml_idp_metadata_xml, saml_sp_key_pem, saml_sp_cert_pem,
			saml_attribute_email, saml_attribute_name, saml_attribute_role,
			oidc_issuer_url, oidc_client_id, oidc_client_secret,
			oidc_claim_email, oidc_claim_name, oidc_claim_role
		) VALUES (
			:id, :tenant_id, :provider_name, :provider_type, :enabled, :auto_provision,
			:default_role, :domains,
			:saml_idp_metadata_xml, :saml_sp_key_pem, :saml_sp_cert_pem,
			:saml_attribute_email, :saml_attribute_name, :saml_attribute_role,
			:oidc_issuer_url, :oidc_client_id, :oidc_client_secret,
			:oidc_claim_email, :oidc_claim_name, :oidc_claim_role
		)`, cfg)
	return err
}

func (s *Store) GetSSOConfig(ctx context.Context, id, tenantID string) (*SSOConfig, error) {
	var cfg SSOConfig
	err := s.db.GetContext(ctx, &cfg,
		ssoSelectAll+` WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (s *Store) ListSSOConfigs(ctx context.Context, tenantID string) ([]*SSOConfig, error) {
	var cfgs []*SSOConfig
	err := s.db.SelectContext(ctx, &cfgs,
		ssoSelectAll+` WHERE tenant_id=$1 ORDER BY created_at`, tenantID)
	return cfgs, err
}

// GetEnabledSSOConfigByDomain returns the first enabled SSO config that claims the given email domain.
func (s *Store) GetEnabledSSOConfigByDomain(ctx context.Context, domain string) (*SSOConfig, error) {
	var cfg SSOConfig
	err := s.db.GetContext(ctx, &cfg,
		ssoSelectAll+` WHERE enabled=TRUE AND $1=ANY(domains) LIMIT 1`, domain)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

// GetEnabledSSOConfig returns the first enabled config of a given type for a tenant.
func (s *Store) GetEnabledSSOConfig(ctx context.Context, tenantID, providerType string) (*SSOConfig, error) {
	var cfg SSOConfig
	err := s.db.GetContext(ctx, &cfg,
		ssoSelectAll+` WHERE tenant_id=$1 AND provider_type=$2 AND enabled=TRUE LIMIT 1`,
		tenantID, providerType)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (s *Store) UpdateSSOConfig(ctx context.Context, cfg *SSOConfig) error {
	_, err := s.db.NamedExecContext(ctx, `
		UPDATE sso_configs SET
			provider_name         = :provider_name,
			enabled               = :enabled,
			auto_provision        = :auto_provision,
			default_role          = :default_role,
			domains               = :domains,
			saml_idp_metadata_xml = :saml_idp_metadata_xml,
			saml_attribute_email  = :saml_attribute_email,
			saml_attribute_name   = :saml_attribute_name,
			saml_attribute_role   = :saml_attribute_role,
			oidc_issuer_url       = :oidc_issuer_url,
			oidc_client_id        = :oidc_client_id,
			oidc_client_secret    = :oidc_client_secret,
			oidc_claim_email      = :oidc_claim_email,
			oidc_claim_name       = :oidc_claim_name,
			oidc_claim_role       = :oidc_claim_role,
			updated_at            = NOW()
		WHERE id=:id AND tenant_id=:tenant_id`, cfg)
	return err
}

func (s *Store) DeleteSSOConfig(ctx context.Context, id, tenantID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sso_configs WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

// GetUserBySSOSubject finds a user provisioned by a specific SSO provider + subject.
func (s *Store) GetUserBySSOSubject(ctx context.Context, provider, subject, tenantID string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM users WHERE sso_provider=$1 AND sso_subject=$2 AND tenant_id=$3`,
		provider, subject, tenantID,
	).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return id, err
}
