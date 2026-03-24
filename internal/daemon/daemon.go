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
	"strings"
	"sync"
	"syscall"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/internal/alert"
	"github.com/agentOnRails/agent-on-rails/internal/audit"
	"github.com/agentOnRails/agent-on-rails/internal/config"
	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
	"github.com/agentOnRails/agent-on-rails/internal/vault"
)

// Daemon manages per-agent HTTP proxy servers.
type Daemon struct {
	cfg     *config.GlobalConfig
	agents  []*agentRuntime
	db      *audit.SQLiteAuditLogger
	alerter *alert.Alerter
	vault   *vault.Vault
	logger  *zap.Logger
	servers []*http.Server
	mu      sync.Mutex
}

// agentRuntime holds the live state for a single agent.
type agentRuntime struct {
	cfg  *config.AgentConfig
	rail *x402.X402Rail
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

	alerter := alert.New(cfg.Alerts.SlackWebhookURL, cfg.Alerts.BudgetThresholdPct, logger)

	d := &Daemon{
		cfg:     cfg,
		db:      db,
		alerter: alerter,
		vault:   v,
		logger:  logger,
	}

	for _, agentCfg := range agents {
		if agentCfg.Rails.X402 == nil || !agentCfg.Rails.X402.Enabled {
			continue
		}

		policy, err := config.BuildX402Policy(cfg, agentCfg)
		if err != nil {
			return nil, fmt.Errorf("daemon: build policy for %s: %w", agentCfg.AgentID, err)
		}

		key, err := v.LoadKey(agentCfg.AgentID, passphrase)
		if err != nil {
			return nil, fmt.Errorf("daemon: load wallet for %s: %w (run `aor credentials set-wallet`)", agentCfg.AgentID, err)
		}

		// Confirm the loaded key matches the wallet_address in config so that
		// EIP-3009 signatures have the correct `from` address.
		derivedAddr := ethcrypto.PubkeyToAddress(key.PublicKey).Hex()
		if !strings.EqualFold(derivedAddr, policy.WalletAddress) {
			return nil, fmt.Errorf(
				"daemon: wallet key mismatch for agent %s: key derives to %s but config wallet_address is %s — update config or re-run `aor credentials set-wallet`",
				agentCfg.AgentID, derivedAddr, policy.WalletAddress,
			)
		}

		policy.PrivateKey = key

		rail, err := x402.NewX402Rail(policy, db, logger)
		if err != nil {
			return nil, fmt.Errorf("daemon: create x402 rail for %s: %w", agentCfg.AgentID, err)
		}

		// Wire budget threshold alert callback.
		rail.Budget().OnThreshold = alerter.BudgetThresholdCallback(agentCfg.AgentID)

		// Rehydrate budget from persistent audit state.
		if err := d.rehydrateBudget(agentCfg.AgentID, rail); err != nil {
			logger.Warn("budget rehydration failed",
				zap.String("agent", agentCfg.AgentID),
				zap.Error(err),
			)
		}

		d.agents = append(d.agents, &agentRuntime{cfg: agentCfg, rail: rail})
	}

	return d, nil
}

// Start launches all agent proxy servers and blocks until SIGINT/SIGTERM or ctx
// is cancelled. Writes a PID file on startup and removes it on exit.
func (d *Daemon) Start(ctx context.Context) error {
	// Wrap context so the budget-persistence goroutine exits cleanly on shutdown.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

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
		d.servers = append(d.servers, srv)
		d.mu.Unlock()
		d.logger.Info("agent proxy started",
			zap.String("agent", ar.cfg.AgentID),
			zap.Int("port", ar.cfg.ProxyPort),
		)
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

func (d *Daemon) startAgentServer(ar *agentRuntime) (*http.Server, error) {
	handler := x402.NewReverseProxyHandler(ar.rail, ar.cfg.AgentID)
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
	servers := d.servers
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

func (d *Daemon) rehydrateBudget(agentID string, rail *x402.X402Rail) error {
	states, err := d.db.RehydrateBudget(agentID)
	if err != nil {
		return err
	}
	for _, s := range states {
		if time.Now().UTC().Before(s.ResetAt) {
			rail.Budget().Seed(s.Period, s.SpentCents)
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
