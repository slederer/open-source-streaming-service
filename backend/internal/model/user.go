package model

import "time"

type User struct {
	ID        string    `db:"id" json:"id"`
	Email     string    `db:"email" json:"email"`
	Name      string    `db:"name" json:"name"`
	Picture   string    `db:"picture" json:"picture"`
	GoogleID  string    `db:"google_id" json:"-"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

type Session struct {
	ID        string    `db:"id"`
	UserID    string    `db:"user_id"`
	Token     string    `db:"token"`
	ExpiresAt time.Time `db:"expires_at"`
	CreatedAt time.Time `db:"created_at"`
}
