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
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
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
	CreatedBy       string     `db:"created_by"       json:"created_by"`
	TOTPSecret      string     `db:"totp_secret"      json:"-"`
	TOTPEnabled     bool       `db:"totp_enabled"     json:"totp_enabled"`
	TOTPBackupCodes string     `db:"totp_backup_codes" json:"-"`
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

// Authenticate verifies username/password and returns the user + signed JWT.
func (m *Manager) Authenticate(ctx context.Context, username, password string) (*User, string, error) {
	u, err := m.GetByUsername(ctx, username)
	if err != nil {
		// Return generic error to avoid username enumeration
		return nil, "", fmt.Errorf("invalid credentials")
	}
	if !u.Enabled {
		return nil, "", fmt.Errorf("account disabled")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, "", fmt.Errorf("invalid credentials")
	}

	// Update last_login_at
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
			Issuer:    "oedr",
		},
		Username: u.Username,
		Role:     u.Role,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.jwtSecret)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
