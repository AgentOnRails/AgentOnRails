// Package daemon implements the AgentOnRails proxy daemon.
// The daemon starts one HTTP proxy server per configured agent and routes all
// outbound traffic through the appropriate payment rail.
package daemon

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/alert"
	"github.com/agentOnRails/agent-on-rails/approval"
	"github.com/agentOnRails/agent-on-rails/config"
	"github.com/agentOnRails/agent-on-rails/internal/audit"
	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
	"github.com/agentOnRails/agent-on-rails/rail"
	"github.com/agentOnRails/agent-on-rails/vault"
)

// Daemon manages per-agent HTTP proxy servers.
type Daemon struct {
	cfg        *config.GlobalConfig
	agents     []*agentRuntime
	db         *audit.SQLiteAuditLogger
	alerter    *alert.Alerter
	railAudit  rail.AuditLogger // db wrapped with alert.AuditLogger — what rails actually log through
	vault      *vault.Vault
	ca         *x402.CA // non-nil when HTTPS interception is enabled
	logger     *zap.Logger
	passphrase string // stored (not just used inline) so a policy reload can rebuild a rail later
	approvals  *approval.Registry

	// servers is keyed by agent ID rather than a bare slice so the control
	// API can pause/resume one agent's proxy server without touching any
	// other's — see pauseAgent/resumeAgent in control.go.
	servers       map[string]*http.Server
	controlServer *http.Server
	controlToken  string
	shutdownFn    context.CancelFunc // cancels Start's ctx; set once Start begins, used by the control API's /control/shutdown
	mu            sync.Mutex
}

// agentRuntime holds the live state for a single agent.
type agentRuntime struct {
	cfg  *config.AgentConfig
	rail rail.Rail
}

// New creates a Daemon from configuration. Use Start() to begin serving.
// passphrase is used to decrypt wallet keys from the vault.
func New(
	cfg *config.GlobalConfig,
	agents []*config.AgentConfig,
	passphrase string,
	logger *zap.Logger,
) (*Daemon, error) {
	db, err := audit.NewSQLiteAuditLogger(config.ExpandHomePath(cfg.Daemon.AuditDB))
	if err != nil {
		return nil, fmt.Errorf("daemon: open audit db: %w", err)
	}

	v, err := vault.New(config.ExpandHomePath(cfg.Daemon.VaultDir))
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("daemon: open vault: %w", err)
	}

	// Any failure after this point must close the audit DB to avoid leaking the
	// file handle (and, on Windows, a lock on audit.db). Cleared once New succeeds.
	dbToClose := db
	defer func() {
		if dbToClose != nil {
			dbToClose.Close()
		}
	}()

	var ca *x402.CA
	if cfg.Daemon.HTTPSIntercept {
		ca, err = x402.LoadOrCreateCA(config.ExpandHomePath(cfg.Daemon.CADir))
		if err != nil {
			return nil, fmt.Errorf("daemon: load interception CA: %w", err)
		}
		logger.Info("HTTPS interception enabled — install this CA in your agent's trust store",
			zap.String("ca_cert", ca.CertPath()),
		)
	}

	alerter := alert.New(cfg.Alerts.SlackWebhookURL, cfg.Alerts.BudgetThresholdPct, logger)

	d := &Daemon{
		cfg:        cfg,
		db:         db,
		alerter:    alerter,
		railAudit:  &alert.AuditLogger{Inner: db, Alerter: alerter},
		vault:      v,
		ca:         ca,
		logger:     logger,
		passphrase: passphrase,
		approvals:  approval.NewRegistry(),
		servers:    make(map[string]*http.Server),
	}

	for _, agentCfg := range agents {
		active, _, err := d.buildAgentRail(agentCfg)
		if err != nil {
			return nil, err
		}
		if active == nil {
			continue
		}

		// Rehydrate budget from persistent audit state.
		if err := d.rehydrateBudget(agentCfg.AgentID, active); err != nil {
			logger.Warn("budget rehydration failed",
				zap.String("agent", agentCfg.AgentID),
				zap.Error(err),
			)
		}

		d.agents = append(d.agents, &agentRuntime{cfg: agentCfg, rail: active})
	}

	dbToClose = nil // ownership transferred to d; keep the DB open
	return d, nil
}

// Start launches all agent proxy servers and blocks until SIGINT/SIGTERM or ctx
// is cancelled. Writes a PID file on startup and removes it on exit.
func (d *Daemon) Start(ctx context.Context) error {
	// Wrap context so the budget-persistence goroutine exits cleanly on shutdown.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Exposed so the control API's /control/shutdown can trigger the same
	// graceful path below (servers drained, budgets persisted, PID file
	// removed) over HTTP instead of an OS signal — the only shutdown
	// mechanism that works uniformly across platforms (Windows' Process.Signal
	// doesn't support SIGTERM at all; see cmd/aor/commands/start.go's stopCmd).
	d.mu.Lock()
	d.shutdownFn = cancel
	d.mu.Unlock()

	pidPath := config.ExpandHomePath(d.cfg.Daemon.PIDFile)
	if err := writePID(pidPath); err != nil {
		d.logger.Warn("could not write PID file", zap.String("path", pidPath), zap.Error(err))
	}
	defer os.Remove(pidPath)

	for _, ar := range d.agents {
		srv, err := d.startAgentServer(ar)
		if err != nil {
			return fmt.Errorf("daemon: start server for %s: %w", ar.cfg.AgentID, err)
		}
		d.mu.Lock()
		d.servers[ar.cfg.AgentID] = srv
		d.mu.Unlock()
		d.logger.Info("agent proxy started",
			zap.String("agent", ar.cfg.AgentID),
			zap.Int("port", ar.cfg.ProxyPort),
		)
	}

	// A control API bind failure (e.g. its port already in use) degrades to
	// a logged warning rather than aborting the whole daemon — approvals/
	// pause/resume/policy-reload become unavailable for this run, but the
	// actual payment proxy every agent depends on is unaffected. This is
	// an auxiliary control surface, not the core product; it shouldn't be
	// able to take the real thing down.
	if !d.cfg.Daemon.ControlDisabled {
		ctrl, err := d.startControlServer()
		if err != nil {
			d.logger.Warn("control API failed to start — approvals/pause/resume/policy-reload are unavailable this run",
				zap.Error(err))
		} else {
			d.mu.Lock()
			d.controlServer = ctrl
			d.mu.Unlock()
		}
	}

	// Periodically persist in-memory budget state so restarts don't reset counters.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d.persistAllBudgets()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for shutdown signal.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		d.logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
	case <-ctx.Done():
		d.logger.Info("context cancelled, shutting down")
	}

	return d.shutdown()
}

// buildAgentRail builds the one active rail for agentCfg from its
// rails.<name> blocks, exactly the logic New's constructor loop used to
// run inline — extracted so the control API's policy-reload endpoint
// (control.go) can rebuild a single agent's rail the same way at runtime,
// without duplicating (and risking divergence from) startup's own rules:
// unknown rail names error, more than one enabled rail per agent errors,
// and the budget-threshold alert callback is always wired the same way.
// Returns active=nil (no error) if agentCfg has no enabled rail at all.
func (d *Daemon) buildAgentRail(agentCfg *config.AgentConfig) (active rail.Rail, activeRailName string, err error) {
	for railName, rawCfg := range agentCfg.Rails {
		factory, ok := rail.Get(railName)
		if !ok {
			return nil, "", fmt.Errorf("daemon: agent %s: unknown rail %q (not registered in this binary — if this is a commercial/paid rail, run the binary that registers it instead, e.g. aor-pro, and make sure its package is blank-imported before daemon.New is called)", agentCfg.AgentID, railName)
		}

		r, enabled, err := factory(rail.FactoryParams{
			AgentID:    agentCfg.AgentID,
			RawConfig:  rawCfg,
			Global:     d.cfg,
			Vault:      d.vault,
			Passphrase: d.passphrase,
			Audit:      d.railAudit,
			Logger:     d.logger,
			Approvals:  d.approvals,
		})
		if err != nil {
			return nil, "", fmt.Errorf("daemon: build rail %q for %s: %w", railName, agentCfg.AgentID, err)
		}
		if !enabled {
			continue
		}
		if active != nil {
			return nil, "", fmt.Errorf("daemon: agent %s: multiple active rails not yet supported (%s and %s)",
				agentCfg.AgentID, activeRailName, railName)
		}
		active = r
		activeRailName = railName
	}

	if active != nil {
		active.Budget().OnThreshold = d.alerter.BudgetThresholdCallback(agentCfg.AgentID)
	}
	return active, activeRailName, nil
}

func (d *Daemon) startAgentServer(ar *agentRuntime) (*http.Server, error) {
	// The reverse proxy handler (including HTTPS interception) works against
	// any rail.Rail, not just x402 — this is what lets a wrapper like a
	// commercial identity_gate rail serve real traffic through the same path.
	handler := x402.NewReverseProxyHandler(ar.rail, ar.cfg.AgentID, d.ca, d.logger)
	addr := net.JoinHostPort(d.cfg.Daemon.ListenAddr, strconv.Itoa(ar.cfg.ProxyPort))

	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			d.logger.Error("agent server error",
				zap.String("agent", ar.cfg.AgentID),
				zap.Error(err),
			)
		}
	}()

	return srv, nil
}

func (d *Daemon) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	d.mu.Lock()
	servers := make([]*http.Server, 0, len(d.servers)+1)
	for _, srv := range d.servers {
		servers = append(servers, srv)
	}
	if d.controlServer != nil {
		servers = append(servers, d.controlServer)
	}
	d.mu.Unlock()

	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func(s *http.Server) {
			defer wg.Done()
			if err := s.Shutdown(ctx); err != nil {
				d.logger.Warn("server shutdown error", zap.Error(err))
			}
		}(srv)
	}
	wg.Wait()

	// Final budget persist before closing the DB.
	d.persistAllBudgets()

	if err := d.db.Close(); err != nil {
		d.logger.Warn("audit db close error", zap.Error(err))
	}
	d.logger.Info("daemon stopped")
	return nil
}

// persistAllBudgets writes every agent's current in-memory spend totals to the
// audit DB so they survive daemon restarts.
func (d *Daemon) persistAllBudgets() {
	for _, ar := range d.agents {
		snaps := ar.rail.Budget().Snapshot()
		states := make([]audit.BudgetPeriodState, len(snaps))
		for i, s := range snaps {
			states[i] = audit.BudgetPeriodState{
				Period:     s.Period,
				SpentCents: s.SpentCents,
				ResetAt:    s.ResetAt,
			}
		}
		if err := d.db.PersistBudget(ar.cfg.AgentID, states); err != nil {
			d.logger.Warn("budget persist failed",
				zap.String("agent", ar.cfg.AgentID),
				zap.Error(err),
			)
		}
	}
}

func (d *Daemon) rehydrateBudget(agentID string, r rail.Rail) error {
	states, err := d.db.RehydrateBudget(agentID)
	if err != nil {
		return err
	}
	for _, s := range states {
		if time.Now().UTC().Before(s.ResetAt) {
			r.Budget().Seed(s.Period, s.SpentCents)
		}
	}
	return nil
}

// ─── PID file ─────────────────────────────────────────────────────────────────

func writePID(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0600)
}

// ReadPID reads the daemon PID from pidPath.
func ReadPID(pidPath string) (int, error) {
	data, err := os.ReadFile(config.ExpandHomePath(pidPath))
	if err != nil {
		return 0, fmt.Errorf("daemon not running (no PID file at %s)", pidPath)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return 0, fmt.Errorf("invalid PID file: %w", err)
	}
	return pid, nil
}
