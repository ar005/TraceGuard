// internal/apikeys/apikeys.go
//
// API key management for the EDR backend.
//
// Keys are stored in the `api_keys` table. Each key has:
//   - a name/description (e.g. "ci-pipeline", "soc-analyst-1")
//   - a prefix (first 8 chars of the raw key) shown in listings so you
//     can identify which key is which without exposing the full secret
//   - a bcrypt hash of the full key (never stored in plaintext)
//   - optional expiry date
//   - created_at / last_used_at timestamps
//
// The raw key is returned ONCE at creation time and never stored.
// Format:  edr_<32 random hex chars>   e.g.  edr_a1b2c3d4...
//
// Bootstrap: if the api_keys table is empty AND a legacy auth.api_key
// is set in config, it is imported automatically as "legacy-config-key"
// so existing deployments keep working without any manual steps.

package apikeys

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
)

const (
	keyPrefix  = "edr_"
	keyRandLen = 32 // random bytes → 64 hex chars
	bcryptCost = 12
)

// Key is one row from api_keys (hash field omitted from JSON output).
type Key struct {
	ID         string     `db:"id"           json:"id"`
	Name       string     `db:"name"         json:"name"`
	Prefix     string     `db:"prefix"       json:"prefix"`
	Hash       string     `db:"hash"         json:"-"`
	CreatedAt  time.Time  `db:"created_at"   json:"created_at"`
	ExpiresAt  *time.Time `db:"expires_at"   json:"expires_at,omitempty"`
	LastUsedAt *time.Time `db:"last_used_at" json:"last_used_at,omitempty"`
	CreatedBy  string     `db:"created_by"   json:"created_by"`
	Enabled    bool       `db:"enabled"      json:"enabled"`
	Role       string     `db:"role"         json:"role"` // "admin" or "analyst"
}

// CreateResult is returned once at creation — raw_key is never stored.
type CreateResult struct {
	Key    Key    `json:"key"`
	RawKey string `json:"raw_key"`
}

// Manager provides key CRUD and validation.
type Manager struct {
	db *sqlx.DB
}

func New(db *sqlx.DB) *Manager { return &Manager{db: db} }

// ─── CRUD ─────────────────────────────────────────────────────────────────────

// Create generates a new key, stores its bcrypt hash, and returns the raw key.
func (m *Manager) Create(ctx context.Context, name, createdBy string, expiresAt *time.Time) (*CreateResult, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("name is required")
	}
	raw, err := generateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash key: %w", err)
	}
	k := Key{
		ID:        "key-" + randomHex(8),
		Name:      name,
		Prefix:    raw[:8],
		Hash:      string(hash),
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		CreatedBy: createdBy,
		Enabled:   true,
	}
	_, err = m.db.ExecContext(ctx, `
		INSERT INTO api_keys (id, name, prefix, hash, created_at, expires_at, created_by, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, k.ID, k.Name, k.Prefix, k.Hash, k.CreatedAt, k.ExpiresAt, k.CreatedBy, k.Enabled)
	if err != nil {
		return nil, fmt.Errorf("insert key: %w", err)
	}
	return &CreateResult{Key: k, RawKey: raw}, nil
}

// List returns all keys without hashes.
func (m *Manager) List(ctx context.Context) ([]Key, error) {
	var keys []Key
	err := m.db.SelectContext(ctx, &keys,
		`SELECT id,name,prefix,created_at,expires_at,last_used_at,created_by,enabled
		   FROM api_keys ORDER BY created_at DESC`)
	return keys, err
}

// Get returns a single key by ID without hash.
func (m *Manager) Get(ctx context.Context, id string) (*Key, error) {
	var k Key
	err := m.db.GetContext(ctx, &k,
		`SELECT id,name,prefix,created_at,expires_at,last_used_at,created_by,enabled
		   FROM api_keys WHERE id=$1`, id)
	return &k, err
}

// Revoke disables a key (keeps the row for audit trail).
func (m *Manager) Revoke(ctx context.Context, id string) error {
	res, err := m.db.ExecContext(ctx, `UPDATE api_keys SET enabled=FALSE WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("key %q not found", id)
	}
	return nil
}

// Delete permanently removes a key.
func (m *Manager) Delete(ctx context.Context, id string) error {
	res, err := m.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("key %q not found", id)
	}
	return nil
}

// ─── Validation ───────────────────────────────────────────────────────────────

// Validate checks a raw Bearer token against enabled, non-expired DB keys.
// Returns the matching Key on success. Updates last_used_at asynchronously.
func (m *Manager) Validate(ctx context.Context, raw string) (*Key, error) {
	if !strings.HasPrefix(raw, keyPrefix) {
		return nil, fmt.Errorf("invalid key format")
	}
	prefix := raw[:8]

	// Only load rows whose prefix matches — keeps bcrypt calls to 1 typically.
	var candidates []Key
	if err := m.db.SelectContext(ctx, &candidates,
		`SELECT id,name,prefix,hash,created_at,expires_at,last_used_at,created_by,enabled
		   FROM api_keys
		  WHERE prefix=$1 AND enabled=TRUE
		    AND (expires_at IS NULL OR expires_at > NOW())`,
		prefix,
	); err != nil {
		return nil, fmt.Errorf("query keys: %w", err)
	}

	for i := range candidates {
		k := &candidates[i]
		if bcrypt.CompareHashAndPassword([]byte(k.Hash), []byte(raw)) == nil {
			go func(id string) {
				_, _ = m.db.ExecContext(context.Background(),
					`UPDATE api_keys SET last_used_at=NOW() WHERE id=$1`, id)
			}(k.ID)
			return k, nil
		}
	}
	return nil, fmt.Errorf("invalid or expired key")
}

// ─── Bootstrap ────────────────────────────────────────────────────────────────

// Bootstrap imports a legacy plain-text key from config into the api_keys
// table if the table is currently empty. Runs once on startup; safe to call
// on every boot (no-op if keys already exist or legacyKey is empty).
func (m *Manager) Bootstrap(ctx context.Context, legacyKey string) error {
	if legacyKey == "" {
		return nil
	}
	var count int
	if err := m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_keys`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil // already have keys
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(legacyKey), bcryptCost)
	if err != nil {
		return fmt.Errorf("hash legacy key: %w", err)
	}
	prefix := legacyKey
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	_, err = m.db.ExecContext(ctx, `
		INSERT INTO api_keys (id, name, prefix, hash, created_at, created_by, enabled)
		VALUES ('key-legacy','legacy-config-key',$1,$2,NOW(),'bootstrap',TRUE)
		ON CONFLICT DO NOTHING
	`, prefix, string(hash))
	return err
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func generateKey() (string, error) {
	b := make([]byte, keyRandLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return keyPrefix + hex.EncodeToString(b), nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
