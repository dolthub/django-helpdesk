package main

import (
	"context"
	"doltdesk-api/db"
	"doltdesk-api/db/utils"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gocraft/dbr/v2"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	dbPassLen         = 32
	agenticUsersTable = "helpdesk_doltdesk_users"

	idCol           = "id"
	usernameCol     = "username"
	passCol         = "password"
	branchPrefixCol = "branch_prefix"
	dbUserCol       = "db_user"
	dbPassCol       = "db_pass"
)

type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username" db:"name"`
	PasswordHash string `json:"-" db:"password"`
	BranchPrefix string `json:"-" db:"branch_prefix"`
	DbUser       string `json:"-" db:"db_user"`
	DbPass       string `json:"-" db:"db_pass"`
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
	ID        string            `json:"id"`
	UserID    int64             `json:"user_id"`
	Dbp       *utils.DBProvider `json:"-"`
	ExpiresAt time.Time         `json:"expires_at"`
	CreatedAt time.Time         `json:"created_at"`
}

type AuthManager struct {
	db       utils.DBProvider
	sessions map[string]*Session
	mutex    sync.RWMutex
}

func NewAuthManager(dbConnParams db.ConnParams) *AuthManager {
	am := &AuthManager{
		sessions: make(map[string]*Session),
	}

	return am
}

var passChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"

func randomPass(length int) string {
	randBytes := make([]byte, length)

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range randBytes {
		n := rng.Int31n(int32(len(passChars)))
		randBytes[i] = passChars[n]
	}

	return string(randBytes)
}

func (am *AuthManager) CreateUser(ctx context.Context, username, password string) (*User, error) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Check if user already exists
	err = am.db.Transaction(ctx, func(tx *dbr.Tx) error {
		var existing User
		n, err := tx.Select("*").From(agenticUsersTable).Where(
			dbr.Eq("name", username),
		).LoadContext(ctx, &existing)

		if err != nil {
			return fmt.Errorf("error getting user: %w", err)
		} else if n != 0 {
			return fmt.Errorf("user already exists")
		}

		return nil
	})

	if err != nil {
		return nil, ErrUserExists
	}

	user := &User{
		Username:     username,
		PasswordHash: string(hashedPassword),
		BranchPrefix: username + "-",
		DbUser:       username,
		DbPass:       randomPass(dbPassLen),
	}

	err = am.db.Transaction(ctx, func(tx *dbr.Tx) error {
		res, err := tx.InsertInto(agenticUsersTable).
			Columns(usernameCol, passCol, branchPrefixCol, dbUserCol, dbPassCol).
			Record(user).
			ExecContext(ctx)

		if err != nil {
			return fmt.Errorf("error inserting user: %w", err)
		}

		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("error getting affected rows: %w", err)
		} else if n != 1 {
			return fmt.Errorf("0 rows affected")
		}

		id, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("error getting last insert ID: %w", err)
		}

		user.ID = id
		return tx.Commit()
	})

	if err != nil {
		return nil, fmt.Errorf("error creating user: %w", err)
	}

	return user, nil
}

func (am *AuthManager) AuthenticateUser(ctx context.Context, username, password string) (*User, error) {
	var existing User
	err := am.db.Transaction(context.Background(), func(tx *dbr.Tx) error {
		n, err := tx.Select("*").From(agenticUsersTable).Where(
			dbr.Eq("name", username),
		).LoadContext(ctx, &existing)

		if err != nil {
			return fmt.Errorf("error getting user: %w", err)
		} else if n != 0 {
			return fmt.Errorf("user already exists")
		}

		return nil
	})

	if err != nil {
		return nil, ErrInvalidCredentials
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error hashing password: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(existing.PasswordHash), passwordHash); err != nil {
		return nil, ErrInvalidCredentials
	}

	return &existing, nil
}

func generateID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (am *AuthManager) connParams(user, pass, branch string) *db.ConnParams {
	return &db.ConnParams{
		User:   user,
		Pass:   pass,
		Branch: branch,
	}
}

func (am *AuthManager) CreateSession(ctx context.Context, user *User) (*Session, error) {
	sessionID, err := generateID()
	if err != nil {
		return nil, err
	}

	branch := user.BranchPrefix + sessionID
	connParams := am.connParams(user.DbUser, user.DbPass, branch)
	conn, err := db.NewConn(ctx, connParams)
	if err != nil {
		return nil, fmt.Errorf("error creating agent db conn: %w", err)
	}

	dbp, err := utils.NewDBProvider(conn, connParams.DbName+"/"+branch, "")
	if err != nil {
		return nil, fmt.Errorf("error creating agent db provider: %w", err)
	}

	session := &Session{
		ID:        sessionID,
		UserID:    user.ID,
		Dbp:       dbp,
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

func (am *AuthManager) GetUserByID(ctx context.Context, userID int64) (*User, error) {
	var user *User
	err := am.db.Transaction(ctx, func(tx *dbr.Tx) error {
		var existing User
		err := tx.Select("*").From(agenticUsersTable).Where(dbr.Eq(idCol, userID)).LoadOneContext(ctx, &existing)
		if err != nil {
			if err == dbr.ErrNotFound {
				return fmt.Errorf("error getting user: %w", err)
			}
		} else {
			user = &existing
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error getting user: %w", err)
	}

	return user, nil
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

// HTTP Handlers
func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Authenticate user
	user, err := s.authManager.AuthenticateUser(ctx, req.Username, req.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(LoginResponse{
			Message: "Invalid credentials",
		})
		return
	}

	// Create session
	session, err := s.authManager.CreateSession(ctx, user)
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
		user, err := s.authManager.GetUserByID(r.Context(), session.UserID)
		if err != nil {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		// Add user to request context
		ctx := r.Context()
		ctx = contextWithUser(ctx, user)
		ctx = contextWithDB(ctx, session.Dbp)
		r = r.WithContext(ctx)

		next(w, r)
	}
}
