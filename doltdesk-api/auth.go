package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login,omitempty"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Message string `json:"message"`
	User    *User  `json:"user,omitempty"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type AuthManager struct {
	users    map[string]*User
	sessions map[string]*Session
	mutex    sync.RWMutex
}

func NewAuthManager() *AuthManager {
	am := &AuthManager{
		users:    make(map[string]*User),
		sessions: make(map[string]*Session),
	}
	
	// Create default admin user
	adminUser, _ := am.CreateUser("admin", "admin123")
	am.users[adminUser.Username] = adminUser
	
	return am
}

func (am *AuthManager) CreateUser(username, password string) (*User, error) {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	
	// Check if user already exists
	if _, exists := am.users[username]; exists {
		return nil, ErrUserExists
	}
	
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	
	// Generate user ID
	id, err := generateID()
	if err != nil {
		return nil, err
	}
	
	user := &User{
		ID:           id,
		Username:     username,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
	}
	
	am.users[username] = user
	return user, nil
}

func (am *AuthManager) AuthenticateUser(username, password string) (*User, error) {
	am.mutex.RLock()
	user, exists := am.users[username]
	am.mutex.RUnlock()
	
	if !exists {
		return nil, ErrInvalidCredentials
	}
	
	// Check password
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	
	// Update last login
	am.mutex.Lock()
	user.LastLogin = time.Now()
	am.mutex.Unlock()
	
	return user, nil
}

func (am *AuthManager) CreateSession(userID string) (*Session, error) {
	sessionID, err := generateID()
	if err != nil {
		return nil, err
	}
	
	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour sessions
		CreatedAt: time.Now(),
	}
	
	am.mutex.Lock()
	am.sessions[sessionID] = session
	am.mutex.Unlock()
	
	return session, nil
}

func (am *AuthManager) GetSession(sessionID string) (*Session, error) {
	am.mutex.RLock()
	session, exists := am.sessions[sessionID]
	am.mutex.RUnlock()
	
	if !exists {
		return nil, ErrSessionNotFound
	}
	
	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		am.DeleteSession(sessionID)
		return nil, ErrSessionExpired
	}
	
	return session, nil
}

func (am *AuthManager) DeleteSession(sessionID string) {
	am.mutex.Lock()
	delete(am.sessions, sessionID)
	am.mutex.Unlock()
}

func (am *AuthManager) GetUserByID(userID string) (*User, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	
	for _, user := range am.users {
		if user.ID == userID {
			return user, nil
		}
	}
	
	return nil, ErrUserNotFound
}

func (am *AuthManager) CleanupExpiredSessions() {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	
	now := time.Now()
	for sessionID, session := range am.sessions {
		if now.After(session.ExpiresAt) {
			delete(am.sessions, sessionID)
		}
	}
}

func generateID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// HTTP Handlers
func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	// Authenticate user
	user, err := s.authManager.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(LoginResponse{
			Message: "Invalid credentials",
		})
		return
	}
	
	// Create session
	session, err := s.authManager.CreateSession(user.ID)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	
	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		Expires:  session.ExpiresAt,
	})
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{
		Message: "Login successful",
		User:    user,
	})
}

func (s *Server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Get session from cookie
	cookie, err := r.Cookie("session_id")
	if err == nil {
		s.authManager.DeleteSession(cookie.Value)
	}
	
	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
	})
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Message: "Logout successful",
		Status:  "ok",
	})
}

func (s *Server) profileHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// Middleware
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get session from cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		
		// Validate session
		session, err := s.authManager.GetSession(cookie.Value)
		if err != nil {
			http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
			return
		}
		
		// Get user
		user, err := s.authManager.GetUserByID(session.UserID)
		if err != nil {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}
		
		// Add user to request context
		ctx := r.Context()
		ctx = contextWithUser(ctx, user)
		r = r.WithContext(ctx)
		
		next(w, r)
	}
}