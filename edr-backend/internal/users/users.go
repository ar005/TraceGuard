// internal/users/users.go
//
// User management for the EDR admin portal.
//
// Roles:
//   admin   — full access including user/key management
//   analyst — read-only access to events, alerts, agents
//
// Passwords are bcrypt-hashed. A bootstrap admin is created on first run
// with credentials printed to the log (and only the log).
//
// Sessions: POST /api/v1/auth/login returns a signed JWT valid for 12h.
// The JWT carries {sub: user_id, username, role} and is verified by
// sessionMiddleware() in server.go.

package users

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// Role constants.
const (
	RoleAdmin   = "admin"
	RoleAnalyst = "analyst"
)

// User is one row from the users table.
type User struct {
	ID           string     `db:"id"            json:"id"`
	Username     string     `db:"username"      json:"username"`
	Email        string     `db:"email"         json:"email"`
	PasswordHash string     `db:"password_hash" json:"-"`
	Role         string     `db:"role"          json:"role"`
	Enabled      bool       `db:"enabled"       json:"enabled"`
	CreatedAt    time.Time  `db:"created_at"    json:"created_at"`
	LastLoginAt  *time.Time `db:"last_login_at" json:"last_login_at,omitempty"`
	CreatedBy    string     `db:"created_by"    json:"created_by"`
	// TOTP / MFA
	TOTPSecret      string `db:"totp_secret"       json:"-"`                         // base32 secret (empty = not enrolled)
	TOTPEnabled     bool   `db:"totp_enabled"      json:"totp_enabled"`
	TOTPBackupCodes string `db:"totp_backup_codes" json:"-"`                         // JSON array of hashed codes
}

// Claims is the JWT payload.
type Claims struct {
	jwt.RegisteredClaims
	Username string `json:"username"`
	Role     string `json:"role"`
}

// Manager provides user CRUD, auth, and JWT operations.
type Manager struct {
	db        *sqlx.DB
	jwtSecret []byte
}

func New(db *sqlx.DB, jwtSecret []byte) *Manager {
	return &Manager{db: db, jwtSecret: jwtSecret}
}

// ─── Bootstrap ────────────────────────────────────────────────────────────────

// Bootstrap creates the first admin user if the users table is empty.
// Returns the plain-text password (only on creation, empty string otherwise).
func (m *Manager) Bootstrap(ctx context.Context) (username, password string, created bool, err error) {
	var count int
	if err = m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return "", "", false, fmt.Errorf("count users: %w", err)
	}
	if count > 0 {
		return "", "", false, nil
	}

	password = randomHex(10) // 20-char random hex password
	if _, err = m.Create(ctx, "admin", password, "", RoleAdmin, "bootstrap"); err != nil {
		return "", "", false, fmt.Errorf("bootstrap admin: %w", err)
	}
	return "admin", password, true, nil
}

// ─── CRUD ─────────────────────────────────────────────────────────────────────

// Create creates a new user with a hashed password.
func (m *Manager) Create(ctx context.Context, username, password, email, role, createdBy string) (*User, error) {
	if strings.TrimSpace(username) == "" {
		return nil, fmt.Errorf("username is required")
	}
	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}
	if role != RoleAdmin && role != RoleAnalyst {
		return nil, fmt.Errorf("role must be 'admin' or 'analyst'")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	u := &User{
		ID:           "usr-" + randomHex(8),
		Username:     strings.TrimSpace(username),
		Email:        strings.TrimSpace(email),
		PasswordHash: string(hash),
		Role:         role,
		Enabled:      true,
		CreatedAt:    time.Now(),
		CreatedBy:    createdBy,
	}

	_, err = m.db.ExecContext(ctx, `
		INSERT INTO users (id, username, email, password_hash, role, enabled, created_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, u.ID, u.Username, u.Email, u.PasswordHash, u.Role, u.Enabled, u.CreatedAt, u.CreatedBy)
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}
	return u, nil
}

// List returns all users (password hash excluded).
func (m *Manager) List(ctx context.Context) ([]User, error) {
	var users []User
	err := m.db.SelectContext(ctx, &users,
		`SELECT * FROM users ORDER BY created_at ASC`)
	return users, err
}

// Get returns a single user by ID.
func (m *Manager) Get(ctx context.Context, id string) (*User, error) {
	var u User
	err := m.db.GetContext(ctx, &u, `SELECT * FROM users WHERE id=$1`, id)
	return &u, err
}

// GetByUsername returns a user by username (used for login).
func (m *Manager) GetByUsername(ctx context.Context, username string) (*User, error) {
	var u User
	err := m.db.GetContext(ctx, &u, `SELECT * FROM users WHERE username=$1`, username)
	return &u, err
}

// Update updates mutable fields (email, role, enabled). Password unchanged.
func (m *Manager) Update(ctx context.Context, id, email, role string, enabled bool) error {
	if role != RoleAdmin && role != RoleAnalyst {
		return fmt.Errorf("invalid role")
	}
	_, err := m.db.ExecContext(ctx,
		`UPDATE users SET email=$2, role=$3, enabled=$4 WHERE id=$1`,
		id, email, role, enabled)
	return err
}

// ChangePassword changes a user's password.
func (m *Manager) ChangePassword(ctx context.Context, id, newPassword string) error {
	if len(newPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	_, err = m.db.ExecContext(ctx,
		`UPDATE users SET password_hash=$2 WHERE id=$1`, id, string(hash))
	return err
}

// Delete permanently deletes a user.
func (m *Manager) Delete(ctx context.Context, id string) error {
	_, err := m.db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, id)
	return err
}

// ─── Authentication ───────────────────────────────────────────────────────────

// AuthResult describes the outcome of Authenticate.
type AuthResult struct {
	User        *User  `json:"user,omitempty"`
	Token       string `json:"token,omitempty"`
	MFARequired bool   `json:"mfa_required,omitempty"`
	MFAToken    string `json:"mfa_token,omitempty"` // short-lived token to pass to VerifyTOTPLogin
}

// Authenticate verifies username/password. If TOTP is enabled on the account,
// returns MFARequired=true with a temporary MFA token instead of a JWT.
func (m *Manager) Authenticate(ctx context.Context, username, password string) (*AuthResult, error) {
	u, err := m.GetByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	if !u.Enabled {
		return nil, fmt.Errorf("account disabled")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// If TOTP is enabled, return a temporary MFA token instead of a JWT.
	if u.TOTPEnabled && u.TOTPSecret != "" {
		mfaToken, err := m.issueMFAToken(u)
		if err != nil {
			return nil, fmt.Errorf("issue mfa token: %w", err)
		}
		return &AuthResult{
			User:        u,
			MFARequired: true,
			MFAToken:    mfaToken,
		}, nil
	}

	// No TOTP — issue JWT directly.
	now := time.Now()
	_, _ = m.db.ExecContext(ctx, `UPDATE users SET last_login_at=$2 WHERE id=$1`, u.ID, now)
	u.LastLoginAt = &now

	token, err := m.issueJWT(u)
	if err != nil {
		return nil, fmt.Errorf("issue token: %w", err)
	}
	return &AuthResult{User: u, Token: token}, nil
}

// VerifyTOTPLogin validates a TOTP code using the mfa_token from Authenticate.
// On success, issues a full JWT.
func (m *Manager) VerifyTOTPLogin(ctx context.Context, mfaToken, code string) (*User, string, error) {
	claims, err := m.validateMFAToken(mfaToken)
	if err != nil {
		return nil, "", fmt.Errorf("invalid or expired MFA token")
	}

	u, err := m.Get(ctx, claims.Subject)
	if err != nil || !u.Enabled {
		return nil, "", fmt.Errorf("user not found or disabled")
	}

	// Check TOTP code.
	if !totp.Validate(code, u.TOTPSecret) {
		// Check backup codes.
		if !m.consumeBackupCode(ctx, u, code) {
			return nil, "", fmt.Errorf("invalid TOTP code")
		}
	}

	// Update last_login_at.
	now := time.Now()
	_, _ = m.db.ExecContext(ctx, `UPDATE users SET last_login_at=$2 WHERE id=$1`, u.ID, now)
	u.LastLoginAt = &now

	token, err := m.issueJWT(u)
	if err != nil {
		return nil, "", fmt.Errorf("issue token: %w", err)
	}
	return u, token, nil
}

// ValidateToken parses and validates a JWT, returning its claims.
func (m *Manager) ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// ─── JWT helpers ──────────────────────────────────────────────────────────────

// IssueToken issues a JWT for an already-authenticated user (e.g. refresh flow).
func (m *Manager) IssueToken(u *User) (string, error) {
	return m.issueJWT(u)
}

func (m *Manager) issueJWT(u *User) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(12 * time.Hour)),
			Issuer:    "TraceGuard",
		},
		Username: u.Username,
		Role:     u.Role,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.jwtSecret)
}

// ─── TOTP / MFA ──────────────────────────────────────────────────────────────

// TOTPSetupResult is returned when starting TOTP enrollment.
type TOTPSetupResult struct {
	Secret      string   `json:"secret"`       // base32 secret
	URL         string   `json:"url"`          // otpauth:// URI for QR code
	BackupCodes []string `json:"backup_codes"` // one-time recovery codes
}

// SetupTOTP generates a new TOTP secret for a user (does NOT enable it yet).
// The caller must verify the user can produce a valid code before confirming.
func (m *Manager) SetupTOTP(ctx context.Context, userID string) (*TOTPSetupResult, error) {
	u, err := m.Get(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "TraceGuard",
		AccountName: u.Username,
	})
	if err != nil {
		return nil, fmt.Errorf("generate TOTP secret: %w", err)
	}

	// Generate 8 backup codes.
	backupCodes := make([]string, 8)
	for i := range backupCodes {
		backupCodes[i] = randomHex(4) // 8-char hex codes
	}

	// Hash backup codes for storage.
	hashedCodes := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		h, _ := bcrypt.GenerateFromPassword([]byte(code), bcrypt.MinCost)
		hashedCodes[i] = string(h)
	}
	codesJSON, _ := json.Marshal(hashedCodes)

	// Store the secret and backup codes (TOTP not yet enabled).
	_, err = m.db.ExecContext(ctx,
		`UPDATE users SET totp_secret=$2, totp_backup_codes=$3 WHERE id=$1`,
		userID, key.Secret(), string(codesJSON))
	if err != nil {
		return nil, fmt.Errorf("save TOTP secret: %w", err)
	}

	return &TOTPSetupResult{
		Secret:      key.Secret(),
		URL:         key.URL(),
		BackupCodes: backupCodes,
	}, nil
}

// ConfirmTOTP verifies a code against the pending secret and enables TOTP.
func (m *Manager) ConfirmTOTP(ctx context.Context, userID, code string) error {
	u, err := m.Get(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	if u.TOTPSecret == "" {
		return fmt.Errorf("TOTP not set up — call SetupTOTP first")
	}
	if !totp.Validate(code, u.TOTPSecret) {
		return fmt.Errorf("invalid TOTP code")
	}

	_, err = m.db.ExecContext(ctx,
		`UPDATE users SET totp_enabled=TRUE WHERE id=$1`, userID)
	return err
}

// DisableTOTP removes TOTP from a user account.
func (m *Manager) DisableTOTP(ctx context.Context, userID string) error {
	_, err := m.db.ExecContext(ctx,
		`UPDATE users SET totp_secret='', totp_enabled=FALSE, totp_backup_codes='[]' WHERE id=$1`,
		userID)
	return err
}

// consumeBackupCode checks if the code matches any backup code. If so, removes it.
func (m *Manager) consumeBackupCode(ctx context.Context, u *User, code string) bool {
	if u.TOTPBackupCodes == "" || u.TOTPBackupCodes == "[]" {
		return false
	}
	var hashedCodes []string
	if err := json.Unmarshal([]byte(u.TOTPBackupCodes), &hashedCodes); err != nil {
		return false
	}

	for i, h := range hashedCodes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(code)) == nil {
			// Remove the used code.
			hashedCodes = append(hashedCodes[:i], hashedCodes[i+1:]...)
			updated, _ := json.Marshal(hashedCodes)
			_, _ = m.db.ExecContext(ctx,
				`UPDATE users SET totp_backup_codes=$2 WHERE id=$1`,
				u.ID, string(updated))
			return true
		}
	}
	return false
}

// ─── MFA Token (short-lived JWT for the TOTP verification step) ──────────────

// MFAClaims is a short-lived JWT issued after password validation but before TOTP.
type MFAClaims struct {
	jwt.RegisteredClaims
	Purpose string `json:"purpose"` // "mfa"
}

func (m *Manager) issueMFAToken(u *User) (string, error) {
	claims := MFAClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)), // 5 min to enter TOTP
			Issuer:    "TraceGuard-mfa",
		},
		Purpose: "mfa",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.jwtSecret)
}

func (m *Manager) validateMFAToken(tokenString string) (*MFAClaims, error) {
	claims := &MFAClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return m.jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid MFA token")
	}
	if claims.Purpose != "mfa" {
		return nil, fmt.Errorf("not an MFA token")
	}
	return claims, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
