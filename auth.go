package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
)

// Auth — простая сессионная авторизация (один пользователь из env).
type Auth struct {
	user     string
	pass     string
	mu       sync.Mutex
	sessions map[string]string // token -> username
}

const sessionCookie = "secscan_session"

func NewAuth(user, pass string) *Auth {
	return &Auth{user: user, pass: pass, sessions: map[string]string{}}
}

func (a *Auth) Login(user, pass string) (string, bool) {
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(user)), []byte(strings.ToLower(a.user))) != 1 {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(pass), []byte(a.pass)) != 1 {
		return "", false
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", false
	}
	token := hex.EncodeToString(buf)
	a.mu.Lock()
	a.sessions[token] = user
	a.mu.Unlock()
	return token, true
}

func (a *Auth) Check(token string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.sessions[token]
	return ok
}

func (a *Auth) Logout(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, token)
}

// requireAuth пропускает запрос только с валидной сессией.
func (a *Auth) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || !a.Check(c.Value) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}
