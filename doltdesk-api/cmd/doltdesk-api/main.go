package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

type Server struct {
	port        string
	authManager *AuthManager
}

type Response struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Service   string    `json:"service"`
}

func NewServer() *Server {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	return &Server{
		port:        port,
		authManager: NewAuthManager(),
	}
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Service:   "doltdesk-api",
	}
	json.NewEncoder(w).Encode(response)
}

func (s *Server) rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := Response{
		Message: "Welcome to DoltDesk API",
		Status:  "ok",
	}
	json.NewEncoder(w).Encode(response)
}

func (s *Server) setupRoutes() *mux.Router {
	router := mux.NewRouter()
	
	// API routes
	api := router.PathPrefix("/api/v1").Subrouter()
	
	// Public routes
	api.HandleFunc("/health", s.healthHandler).Methods("GET")
	api.HandleFunc("/", s.rootHandler).Methods("GET")
	api.HandleFunc("/login", s.loginHandler).Methods("POST")
	api.HandleFunc("/logout", s.logoutHandler).Methods("POST")
	
	// Protected routes
	api.HandleFunc("/profile", s.authMiddleware(s.profileHandler)).Methods("GET")
	api.HandleFunc("/protected", s.authMiddleware(s.protectedHandler)).Methods("GET")
	
	// Root route
	router.HandleFunc("/", s.rootHandler).Methods("GET")
	
	return router
}

func (s *Server) protectedHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"message": "This is a protected endpoint",
		"user":    user.Username,
		"status":  "authenticated",
	}
	json.NewEncoder(w).Encode(response)
}

func (s *Server) Start() error {
	router := s.setupRoutes()
	
	// Start session cleanup goroutine
	go s.startSessionCleanup()
	
	log.Printf("Starting DoltDesk API server on port %s", s.port)
	log.Printf("Default admin user: admin / admin123")
	return http.ListenAndServe(":"+s.port, router)
}

func (s *Server) startSessionCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for range ticker.C {
		s.authManager.CleanupExpiredSessions()
		log.Println("Cleaned up expired sessions")
	}
}

func main() {
	server := NewServer()
	log.Fatal(server.Start())
}