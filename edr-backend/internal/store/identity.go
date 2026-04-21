// internal/store/identity.go
// Identity graph + asset inventory store methods (XDR Phase 2).

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/youredr/edr-backend/internal/models"
)

// ── Identity graph ────────────────────────────────────────────────────────────

// UpsertIdentity inserts or updates an identity_graph row keyed on canonical_uid.
// On conflict, it merges aliases and account_ids and updates mutable fields.
func (s *Store) UpsertIdentity(ctx context.Context, rec *models.IdentityRecord) error {
	if rec.ID == "" {
		rec.ID = uuid.New().String()
	}
	rec.UpdatedAt = time.Now()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO identity_graph
		  (id, canonical_uid, display_name, email, department,
		   account_ids, aliases, risk_score, risk_factors,
		   is_privileged, agent_ids, last_login_at, last_seen_src, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (canonical_uid) DO UPDATE SET
		  display_name  = EXCLUDED.display_name,
		  email         = CASE WHEN EXCLUDED.email != '' THEN EXCLUDED.email ELSE identity_graph.email END,
		  department    = CASE WHEN EXCLUDED.department != '' THEN EXCLUDED.department ELSE identity_graph.department END,
		  account_ids   = identity_graph.account_ids || EXCLUDED.account_ids,
		  aliases       = (SELECT array_agg(DISTINCT a) FROM unnest(identity_graph.aliases || EXCLUDED.aliases) a),
		  is_privileged = identity_graph.is_privileged OR EXCLUDED.is_privileged,
		  agent_ids     = (SELECT array_agg(DISTINCT a) FROM unnest(identity_graph.agent_ids || EXCLUDED.agent_ids) a),
		  last_seen_src = CASE WHEN EXCLUDED.last_seen_src != '' THEN EXCLUDED.last_seen_src ELSE identity_graph.last_seen_src END,
		  updated_at    = NOW()`,
		rec.ID, rec.CanonicalUID, rec.DisplayName, rec.Email, rec.Department,
		rec.AccountIDs, pq.Array(rec.Aliases), rec.RiskScore, rec.RiskFactors,
		rec.IsPrivileged, pq.Array(rec.AgentIDs), rec.LastLoginAt, rec.LastLoginIP, rec.UpdatedAt,
	)
	return err
}

// ListIdentities returns identity_graph rows, ordered by risk_score DESC.
func (s *Store) ListIdentities(ctx context.Context, limit, offset int) ([]models.IdentityRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows []models.IdentityRecord
	err := s.rdb().SelectContext(ctx, &rows, `
		SELECT id, canonical_uid, display_name, email, department,
		       account_ids, aliases, risk_score, risk_factors,
		       is_privileged, agent_ids, last_login_at, last_seen_src, updated_at
		FROM identity_graph
		ORDER BY risk_score DESC, updated_at DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	return rows, err
}

// TouchIdentityLogin updates last_login_at and last_seen_src for a canonical_uid.
func (s *Store) TouchIdentityLogin(ctx context.Context, uid, srcIP string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE identity_graph
		SET last_login_at = NOW(),
		    last_seen_src = $2,
		    updated_at    = NOW()
		WHERE canonical_uid = $1`, uid, srcIP)
	return err
}

// UpdateIdentityRisk stores a new risk score + factors for the given uid.
func (s *Store) UpdateIdentityRisk(ctx context.Context, uid string, score int16, factors []string) error {
	b, _ := json.Marshal(factors)
	_, err := s.db.ExecContext(ctx, `
		UPDATE identity_graph
		SET risk_score   = $2,
		    risk_factors = $3::jsonb,
		    updated_at   = NOW()
		WHERE canonical_uid = $1`, uid, score, string(b))
	return err
}

// DecayAllRiskScores reduces every identity's risk_score by decayAmount (floor 0).
// Returns the number of rows updated.
func (s *Store) DecayAllRiskScores(ctx context.Context, decayAmount int16) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE identity_graph
		SET risk_score = GREATEST(0, risk_score - $1),
		    updated_at = NOW()
		WHERE risk_score > 0`, decayAmount)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// TopRiskyIdentities returns the top N identities by risk score.
func (s *Store) TopRiskyIdentities(ctx context.Context, n int) ([]models.IdentityRecord, error) {
	if n <= 0 {
		n = 10
	}
	var rows []models.IdentityRecord
	err := s.rdb().SelectContext(ctx, &rows, `
		SELECT id, canonical_uid, display_name, email, department,
		       account_ids, aliases, risk_score, risk_factors,
		       is_privileged, agent_ids, last_login_at, last_seen_src, updated_at
		FROM identity_graph
		WHERE risk_score > 0
		ORDER BY risk_score DESC
		LIMIT $1`, n)
	return rows, err
}

// ── Asset inventory ───────────────────────────────────────────────────────────

// UpsertAsset inserts or updates an asset_inventory row keyed on id.
// Cloud assets use cloud_resource_id as the stable key; endpoint assets use agent_id.
func (s *Store) UpsertAsset(ctx context.Context, a *models.AssetRecord) error {
	if a.ID == "" {
		a.ID = uuid.New().String()
	}
	now := time.Now()
	if a.FirstSeenAt.IsZero() {
		a.FirstSeenAt = now
	}
	a.LastSeenAt = now

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO asset_inventory
		  (id, asset_type, hostname, ip_addresses, mac_addresses, os, os_version,
		   cloud_provider, cloud_region, cloud_account, cloud_resource_id,
		   agent_id, tags, risk_score, criticality, owner_uid,
		   first_seen_at, last_seen_at, source_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		ON CONFLICT (id) DO UPDATE SET
		  hostname         = CASE WHEN EXCLUDED.hostname != '' THEN EXCLUDED.hostname ELSE asset_inventory.hostname END,
		  ip_addresses     = (SELECT array_agg(DISTINCT a) FROM unnest(asset_inventory.ip_addresses || EXCLUDED.ip_addresses) a),
		  os               = CASE WHEN EXCLUDED.os != '' THEN EXCLUDED.os ELSE asset_inventory.os END,
		  os_version       = CASE WHEN EXCLUDED.os_version != '' THEN EXCLUDED.os_version ELSE asset_inventory.os_version END,
		  tags             = (SELECT array_agg(DISTINCT a) FROM unnest(asset_inventory.tags || EXCLUDED.tags) a),
		  owner_uid        = CASE WHEN EXCLUDED.owner_uid != '' THEN EXCLUDED.owner_uid ELSE asset_inventory.owner_uid END,
		  last_seen_at     = NOW(),
		  source_id        = EXCLUDED.source_id`,
		a.ID, a.AssetType, a.Hostname, pq.Array(a.IPAddresses), pq.Array(a.MACAddresses),
		a.OS, a.OSVersion, a.CloudProvider, a.CloudRegion, a.CloudAccount, a.CloudResourceID,
		nullString(a.AgentID), pq.Array(a.Tags), a.RiskScore, a.Criticality, a.OwnerUID,
		a.FirstSeenAt, a.LastSeenAt, nullString(a.SourceID),
	)
	return err
}

// ListAssets returns asset_inventory rows ordered by criticality and last_seen_at.
func (s *Store) ListAssets(ctx context.Context, assetType string, limit, offset int) ([]models.AssetRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows []models.AssetRecord
	if assetType != "" {
		err := s.rdb().SelectContext(ctx, &rows, `
			SELECT id, asset_type, hostname, ip_addresses, mac_addresses, os, os_version,
			       cloud_provider, cloud_region, cloud_account, cloud_resource_id,
			       COALESCE(agent_id, '') AS agent_id, tags, risk_score, criticality, owner_uid,
			       first_seen_at, last_seen_at, COALESCE(source_id, '') AS source_id
			FROM asset_inventory
			WHERE asset_type = $1
			ORDER BY criticality DESC, last_seen_at DESC
			LIMIT $2 OFFSET $3`, assetType, limit, offset)
		return rows, err
	}
	err := s.rdb().SelectContext(ctx, &rows, `
		SELECT id, asset_type, hostname, ip_addresses, mac_addresses, os, os_version,
		       cloud_provider, cloud_region, cloud_account, cloud_resource_id,
		       COALESCE(agent_id, '') AS agent_id, tags, risk_score, criticality, owner_uid,
		       first_seen_at, last_seen_at, COALESCE(source_id, '') AS source_id
		FROM asset_inventory
		ORDER BY criticality DESC, last_seen_at DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	return rows, err
}

// GetAssetByAgentID returns the asset_inventory row for a given agent_id.
func (s *Store) GetAssetByAgentID(ctx context.Context, agentID string) (*models.AssetRecord, error) {
	var a models.AssetRecord
	err := s.rdb().GetContext(ctx, &a, `
		SELECT id, asset_type, hostname, ip_addresses, mac_addresses, os, os_version,
		       cloud_provider, cloud_region, cloud_account, cloud_resource_id,
		       COALESCE(agent_id, '') AS agent_id, tags, risk_score, criticality, owner_uid,
		       first_seen_at, last_seen_at, COALESCE(source_id, '') AS source_id
		FROM asset_inventory WHERE agent_id = $1`, agentID)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// AssetCount returns the total number of asset_inventory rows, optionally filtered by type.
func (s *Store) AssetCount(ctx context.Context, assetType string) (int64, error) {
	var n int64
	var err error
	if assetType != "" {
		err = s.rdb().GetContext(ctx, &n, `SELECT COUNT(*) FROM asset_inventory WHERE asset_type = $1`, assetType)
	} else {
		err = s.rdb().GetContext(ctx, &n, `SELECT COUNT(*) FROM asset_inventory`)
	}
	return n, err
}

// ── helpers ───────────────────────────────────────────────────────────────────

func nullString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// NormalizeUID returns a canonical lowercase user identifier suitable for
// identity_graph lookups.  It handles the most common formats:
//   - email: "Alice@Corp.com"   → "alice@corp.com"
//   - UPN:   "alice@corp.com"   → "alice@corp.com"
//   - SAM:   "CORP\\alice"      → "alice"  (strips domain prefix)
//   - Okta:  "00u1xyz"          → "00u1xyz" (opaque, kept as-is)
func NormalizeUID(raw string) string {
	if raw == "" {
		return ""
	}
	// lowercase first
	s := ""
	for _, r := range raw {
		if r >= 'A' && r <= 'Z' {
			s += string(r + 32)
		} else {
			s += string(r)
		}
	}
	// strip "DOMAIN\user" → "user"
	for i, c := range s {
		if c == '\\' {
			return fmt.Sprintf("%s", s[i+1:])
		}
	}
	return s
}
