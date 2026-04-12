package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/slederer/open-source-streaming-service/backend/internal/model"
)

func (s *Store) UpsertUser(ctx context.Context, googleID, email, name, picture string) (*model.User, error) {
	var u model.User
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO users (google_id, email, name, picture)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (google_id) DO UPDATE SET
			email = EXCLUDED.email,
			name = EXCLUDED.name,
			picture = EXCLUDED.picture
		RETURNING id, email, name, picture, google_id, created_at`,
		googleID, email, name, picture,
	).Scan(&u.ID, &u.Email, &u.Name, &u.Picture, &u.GoogleID, &u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("upserting user: %w", err)
	}
	return &u, nil
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	var u model.User
	err := s.db.GetContext(ctx, &u, `SELECT * FROM users WHERE id = $1`, id)
	if err != nil {
		return nil, fmt.Errorf("getting user %s: %w", id, err)
	}
	return &u, nil
}

func (s *Store) CreateSession(ctx context.Context, userID string, duration time.Duration) (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}

	expiresAt := time.Now().Add(duration)
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sessions (user_id, token, expires_at)
		VALUES ($1, $2, $3)`,
		userID, token, expiresAt)
	if err != nil {
		return "", fmt.Errorf("creating session: %w", err)
	}

	return token, nil
}

func (s *Store) GetSessionUser(ctx context.Context, token string) (*model.User, error) {
	var u model.User
	err := s.db.GetContext(ctx, &u, `
		SELECT u.* FROM users u
		JOIN sessions s ON u.id = s.user_id
		WHERE s.token = $1 AND s.expires_at > now()`, token)
	if err != nil {
		return nil, fmt.Errorf("getting session user: %w", err)
	}
	return &u, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token = $1`, token)
	return err
}

func (s *Store) CleanExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	return err
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
