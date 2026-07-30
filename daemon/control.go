package daemon

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/agentOnRails/agent-on-rails/config"
)

// Before this file existed, the daemon was PID-file/signal-controlled only —
// no running-daemon API of any kind, which is also why x402's
// RequireApprovalAboveCents had nowhere to route a pending decision to and
// failed closed, permanently, whenever configured (see CHANGELOG.md's
// [0.1.0] entry). This file is that missing route: a localhost-by-default,
// bearer-token-authenticated HTTP surface exposing approve/deny for held
// payments, pause/resume for one agent's proxy server, and a policy reload —
// all without restarting the daemon process or any other agent. Shared
// surface: both a future view-only dashboard and a full-control one
// read/write the same API.

const controlTokenByteLen = 32

// startControlServer loads or creates the control API's bearer token and
// starts listening. Returns an error only for a genuine startup failure
// (token I/O, port already in use) — never because approvals/pause/resume
// aren't wanted; use GlobalConfig.Daemon.ControlDisabled for that instead.
func (d *Daemon) startControlServer() (*http.Server, error) {
	tokenPath := config.ExpandHomePath(d.cfg.Daemon.ControlTokenFile)
	token, err := loadOrCreateControlToken(tokenPath)
	if err != nil {
		return nil, err
	}
	d.controlToken = token

	addr := d.cfg.Daemon.ControlAddr
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}

	if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil && !isLoopbackHost(host) {
		d.logger.Warn("control API bound to a non-loopback address — this exposes payment-approval and agent-pause/resume control to anyone who can reach this port with the token",
			zap.String("addr", addr))
	}

	srv := &http.Server{
		Handler:      d.controlHandler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			d.logger.Error("control API server error", zap.Error(err))
		}
	}()
	d.logger.Info("control API started", zap.String("addr", addr), zap.String("token_file", tokenPath))
	return srv, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ─── Auth ───────────────────────────────────────────────────────────────────

// loadOrCreateControlToken mirrors Dispatch's own token.go in the private
// repo (GenerateToken/LoadOrCreateToken/ConstantTimeEqual) — deliberately a
// small independent copy rather than a cross-repo dependency for something
// this generic, the same call cargorail.go's readAndRestoreBody doc comment
// makes for its own copy of a similarly small, generic helper.
func loadOrCreateControlToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("daemon: read control token %s: %w", path, err)
	}

	b := make([]byte, controlTokenByteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("daemon: generate control token: %w", err)
	}
	token := hex.EncodeToString(b)

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", fmt.Errorf("daemon: create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		return "", fmt.Errorf("daemon: write control token %s: %w", path, err)
	}
	return token, nil
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (d *Daemon) requireControlAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.URL.Query().Get("token")
		if authz := r.Header.Get("Authorization"); strings.HasPrefix(authz, "Bearer ") {
			got = strings.TrimPrefix(authz, "Bearer ")
		}
		if got == "" || !constantTimeEqual(got, d.controlToken) {
			http.Error(w, "daemon: missing or invalid control token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ─── Routes ─────────────────────────────────────────────────────────────────

func (d *Daemon) controlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /control/approvals", d.requireControlAuth(http.HandlerFunc(d.handleListApprovals)))
	mux.Handle("POST /control/approvals/{id}/approve", d.requireControlAuth(http.HandlerFunc(d.handleResolveApproval(true))))
	mux.Handle("POST /control/approvals/{id}/deny", d.requireControlAuth(http.HandlerFunc(d.handleResolveApproval(false))))
	mux.Handle("POST /control/agents/{id}/pause", d.requireControlAuth(http.HandlerFunc(d.handlePauseAgent)))
	mux.Handle("POST /control/agents/{id}/resume", d.requireControlAuth(http.HandlerFunc(d.handleResumeAgent)))
	mux.Handle("POST /control/agents/{id}/policy", d.requireControlAuth(http.HandlerFunc(d.handleReloadPolicy)))
	return mux
}

func (d *Daemon) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.approvals.List())
}

// handleResolveApproval returns a handler resolving a pending approval as
// approved (true) or denied (false) — one function, parameterized by
// outcome, rather than two near-identical handlers.
func (d *Daemon) handleResolveApproval(approved bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := d.approvals.Resolve(id, approved); err != nil {
			http.Error(w, "daemon: "+err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (d *Daemon) handlePauseAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := d.pauseAgent(id); err != nil {
		http.Error(w, "daemon: "+err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d *Daemon) handleResumeAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := d.resumeAgent(id); err != nil {
		http.Error(w, "daemon: "+err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleReloadPolicy replaces one agent's rails.* configuration and
// restarts just that agent's proxy server against it. The request body is
// the new rails: mapping directly (the same shape an agent's YAML config
// file's own "rails:" key holds), not a full agent config document — e.g.:
//
//	x402:
//	  enabled: true
//	  daily_limit_usd: "10.00"
//	  ...
//
// A body that fails to parse or validate leaves the agent's current policy
// and running server completely untouched — rebuild-then-swap, never
// tear-down-then-rebuild, so a bad request can't take down a working agent.
func (d *Daemon) handleReloadPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	defer r.Body.Close()

	var rawRails config.RailsConfig
	dec := yaml.NewDecoder(r.Body)
	if err := dec.Decode(&rawRails); err != nil {
		http.Error(w, "daemon: parse request body as YAML rails mapping: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := d.reloadAgentPolicy(id, rawRails); err != nil {
		http.Error(w, "daemon: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// ─── Agent lifecycle: pause / resume / policy reload ───────────────────────

func (d *Daemon) findAgent(agentID string) (*agentRuntime, bool) {
	for _, ar := range d.agents {
		if ar.cfg.AgentID == agentID {
			return ar, true
		}
	}
	return nil, false
}

// pauseAgent gracefully shuts down agentID's proxy server (draining
// in-flight requests to completion first) without touching any other
// agent or the daemon process itself. The agentRuntime stays in d.agents,
// just with no server currently listening for it — resumeAgent starts a
// fresh one on the same port.
func (d *Daemon) pauseAgent(agentID string) error {
	d.mu.Lock()
	srv, ok := d.servers[agentID]
	if ok {
		delete(d.servers, agentID)
	}
	d.mu.Unlock()
	if !ok {
		return fmt.Errorf("agent %q is not running", agentID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("pause agent %q: %w", agentID, err)
	}
	d.logger.Info("agent paused", zap.String("agent", agentID))
	return nil
}

// resumeAgent starts a fresh proxy server for an agent previously paused
// (or one whose server otherwise isn't running), on its configured port.
func (d *Daemon) resumeAgent(agentID string) error {
	ar, ok := d.findAgent(agentID)
	if !ok {
		return fmt.Errorf("unknown agent %q", agentID)
	}

	d.mu.Lock()
	_, running := d.servers[agentID]
	d.mu.Unlock()
	if running {
		return fmt.Errorf("agent %q is already running", agentID)
	}

	srv, err := d.startAgentServer(ar)
	if err != nil {
		return fmt.Errorf("resume agent %q: %w", agentID, err)
	}
	d.mu.Lock()
	d.servers[agentID] = srv
	d.mu.Unlock()
	d.logger.Info("agent resumed", zap.String("agent", agentID), zap.Int("port", ar.cfg.ProxyPort))
	return nil
}

// reloadAgentPolicy rebuilds agentID's rail from rawRails and, only if that
// succeeds, swaps it in and restarts that one agent's proxy server so the
// new policy takes effect — the in-flight in-memory budget spend carries
// over to the new rail's tracker (a policy reload shouldn't silently reset
// today's spend counters back to zero). ReverseProxyHandler captures its
// rail.Rail at construction time (see rail/... consumers of
// x402.NewReverseProxyHandler), so there is no way to swap the rail under
// an already-running server without restarting it — the brief reconnect
// window this causes for THIS agent only (others are untouched) is an
// accepted, documented tradeoff against the much larger change a
// mutex-guarded indirection in every rail's proxy handler would require
// for what should stay a rare operation.
func (d *Daemon) reloadAgentPolicy(agentID string, rawRails config.RailsConfig) error {
	ar, ok := d.findAgent(agentID)
	if !ok {
		return fmt.Errorf("unknown agent %q", agentID)
	}

	newCfg := *ar.cfg
	newCfg.Rails = rawRails
	newRail, _, err := d.buildAgentRail(&newCfg)
	if err != nil {
		return fmt.Errorf("build new policy: %w", err)
	}
	if newRail == nil {
		return fmt.Errorf("new policy has no active rail — refusing to reload into a disabled state (use pause instead)")
	}

	for _, snap := range ar.rail.Budget().Snapshot() {
		newRail.Budget().Seed(snap.Period, snap.SpentCents)
	}

	ar.cfg = &newCfg
	ar.rail = newRail

	d.mu.Lock()
	oldSrv, hadServer := d.servers[agentID]
	d.mu.Unlock()
	if hadServer {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := oldSrv.Shutdown(ctx)
		cancel()
		if err != nil {
			d.logger.Warn("policy reload: old server shutdown error", zap.String("agent", agentID), zap.Error(err))
		}
	}

	srv, err := d.startAgentServer(ar)
	if err != nil {
		return fmt.Errorf("restart agent server after policy reload: %w", err)
	}
	d.mu.Lock()
	d.servers[agentID] = srv
	d.mu.Unlock()

	d.logger.Info("agent policy reloaded", zap.String("agent", agentID))
	return nil
}
