package tunnel

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	log "github.com/schollz/logger"
)

// APIServer provides a REST API for tunnel management on the relay.
// Serves JSON endpoints for listing, inspecting, and removing tunnels.
type APIServer struct {
	server *Server
	mux    *http.ServeMux
	token  string // optional bearer token for API auth
	addr   string
	srv    *http.Server
}

// NewAPIServer creates a REST API server attached to the tunnel server.
// Address should be a host:port (e.g. "127.0.0.1:9093").
// If token is non-empty, all requests require Authorization: Bearer <token>.
func NewAPIServer(s *Server, addr, token string) *APIServer {
	a := &APIServer{
		server: s,
		mux:    http.NewServeMux(),
		token:  token,
		addr:   addr,
	}
	a.registerRoutes()
	return a
}

func (a *APIServer) registerRoutes() {
	a.mux.HandleFunc("/api/v1/status", a.authMiddleware(a.handleStatus))
	a.mux.HandleFunc("/api/v1/tunnels", a.authMiddleware(a.handleTunnels))
	a.mux.HandleFunc("/api/v1/tunnels/", a.authMiddleware(a.handleTunnelByID))
}

func (a *APIServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.token != "" {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid authorization"})
				return
			}
			if strings.TrimPrefix(auth, "Bearer ") != a.token {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
				return
			}
		}
		next(w, r)
	}
}

func (a *APIServer) Start() error {
	a.srv = &http.Server{
		Addr:    a.addr,
		Handler: a.mux,
	}
	log.Infof("REST API listening on %s", a.addr)
	return a.srv.ListenAndServe()
}

func (a *APIServer) Stop() error {
	if a.srv != nil {
		return a.srv.Close()
	}
	return nil
}

type apiStatus struct {
	Uptime      string `json:"uptime"`
	Version     string `json:"version,omitempty"`
	Tunnels     int    `json:"tunnels"`
	MetricsPort int    `json:"metrics_port,omitempty"`
}

func (a *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s := a.server.Metrics().Snapshot()
	writeJSON(w, http.StatusOK, apiStatus{
		Uptime:  s.Uptime.Round(time.Second).String(),
		Tunnels: a.server.Registry().Count(),
	})
}

func (a *APIServer) handleTunnels(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		entries := a.server.Registry().List()
		type tunnelView struct {
			ID          string `json:"id"`
			Subdomain   string `json:"subdomain"`
			Type        string `json:"type"`
			LocalAddr   string `json:"local_addr"`
			RemoteAddr  string `json:"remote_addr"`
			PublicPort  int    `json:"public_port,omitempty"`
			Private     bool   `json:"private"`
			HasPassword bool   `json:"has_password"`
			HasToken    bool   `json:"has_token"`
			MaxConns    int    `json:"max_conns,omitempty"`
			CreatedAt   string `json:"created_at"`
			LastSeen    string `json:"last_seen,omitempty"`
			ActiveConns int64  `json:"active_conns"`
			TotalConns  int64  `json:"total_conns"`
		}
		result := make([]tunnelView, 0, len(entries))
		for _, e := range entries {
			stats := e.Stats()
			view := tunnelView{
				ID:          e.ID,
				Subdomain:   e.Subdomain,
				Type:        string(e.Type),
				LocalAddr:   e.LocalAddr,
				RemoteAddr:  e.RemoteAddr,
				PublicPort:  e.PublicPort,
				Private:     e.Private,
				HasPassword: e.Password != "",
				HasToken:    e.Token != "",
				MaxConns:    e.MaxConns,
				CreatedAt:   e.CreatedAt.Format(time.RFC3339),
				LastSeen:    e.LastSeen.Format(time.RFC3339),
				ActiveConns: stats.ActiveConns,
				TotalConns:  stats.TotalConns,
			}
			result = append(result, view)
		}
		writeJSON(w, http.StatusOK, result)

	case http.MethodDelete:
		// DELETE /api/v1/tunnels — delete all tunnels
		// Not implemented for bulk to avoid accidents
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "use DELETE /api/v1/tunnels/{id} for specific tunnel"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (a *APIServer) handleTunnelByID(w http.ResponseWriter, r *http.Request) {
	// Extract tunnel ID from path: /api/v1/tunnels/{id}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/tunnels/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing tunnel ID"})
		return
	}

	entry := a.server.Registry().LookupByID(id)
	if entry == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		stats := entry.Stats()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"id":           entry.ID,
			"subdomain":    entry.Subdomain,
			"type":         string(entry.Type),
			"local_addr":   entry.LocalAddr,
			"remote_addr":  entry.RemoteAddr,
			"public_port":  entry.PublicPort,
			"private":      entry.Private,
			"has_password": entry.Password != "",
			"has_token":    entry.Token != "",
			"max_conns":    entry.MaxConns,
			"created_at":   entry.CreatedAt.Format(time.RFC3339),
			"last_seen":    entry.LastSeen.Format(time.RFC3339),
			"stats": map[string]int64{
				"active_conns": stats.ActiveConns,
				"total_conns":  stats.TotalConns,
				"bytes_in":     stats.TotalBytesIn,
				"bytes_out":    stats.TotalBytesOut,
			},
		})

	case http.MethodDelete:
		a.server.Registry().Unregister(id)
		writeJSON(w, http.StatusOK, map[string]string{"status": "unregistered", "id": id})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// AddAPIServerToServer adds a REST API server to the tunnel Server.
// The API is served on apiAddr (e.g. "127.0.0.1:9093") with optional bearer token auth.
// Call s.APIServer.Start() after s.Start().
func (s *Server) AddAPIServer(apiAddr, apiToken string) *APIServer {
	a := NewAPIServer(s, apiAddr, apiToken)
	s.apiServer = a
	return a
}

// apiServer field is stored on Server — declared in server.go
func (s *Server) StopAPIServer() {
	if s.apiServer != nil {
		s.apiServer.Stop()
	}
}
