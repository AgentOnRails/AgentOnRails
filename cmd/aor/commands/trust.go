package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/agentOnRails/agent-on-rails/config"
)

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Install or remove the AgentOnRails local CA in your OS trust store",
	Long: `Most HTTP clients (Python requests/httpx, Node fetch, curl) can be pointed
at the AgentOnRails CA per-process via "aor run", with no system-wide trust
change at all — prefer that first. "aor trust install" is the fallback for
runtimes that ignore REQUESTS_CA_BUNDLE/SSL_CERT_FILE/NODE_EXTRA_CA_CERTS
(some Go binaries, the JVM, some system tools) and need the CA trusted at
the OS level instead.`,
}

var trustInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the local interception CA into the OS trust store",
	Long: `Installs the AgentOnRails interception CA (~/.aor/ca/aor-ca.crt by default,
or the configured ca_dir) into your operating system's certificate trust
store:

  macOS:   added to your login keychain (security add-trusted-cert)
  Linux:   copied to the system CA directory, then update-ca-certificates
           or update-ca-trust is run (may prompt for sudo)
  Windows: added to the current user's Root store (certutil -addstore -user)

This changes trust settings other processes on this machine will also see.
Run "aor trust uninstall" when you no longer need HTTPS interception.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		caPath, err := resolveCACertPath()
		if err != nil {
			return err
		}
		if _, err := os.Stat(caPath); err != nil {
			return fmt.Errorf("CA certificate not found at %s — start the daemon with https_intercept enabled first so it can generate one: %w", caPath, err)
		}
		if err := installCA(caPath); err != nil {
			return err
		}
		fmt.Printf("Installed %s into the OS trust store.\nRun `aor trust uninstall` to remove it later.\n", caPath)
		return nil
	},
}

var trustUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the AgentOnRails CA from the OS trust store",
	RunE: func(cmd *cobra.Command, args []string) error {
		caPath, err := resolveCACertPath()
		if err != nil {
			return err
		}
		if err := uninstallCA(caPath); err != nil {
			return err
		}
		fmt.Println("Removed the AgentOnRails CA from the OS trust store.")
		return nil
	},
}

func resolveCACertPath() (string, error) {
	caDir := "~/.aor/ca"
	if global, err := config.LoadGlobal(globalConfigPath); err == nil && global.Daemon.CADir != "" {
		caDir = global.Daemon.CADir
	}
	return filepath.Join(config.ExpandHomePath(caDir), "aor-ca.crt"), nil
}

// installCA and uninstallCA shell out to the OS-native trust store tool.
// Commands inherit the parent's stdio so a sudo/password prompt (Linux) or
// keychain prompt (macOS) can actually be answered interactively.

func installCA(caPath string) error {
	switch runtime.GOOS {
	case "darwin":
		keychain, err := loginKeychainPath()
		if err != nil {
			return err
		}
		return runInteractive("security", "add-trusted-cert", "-r", "trustRoot", "-k", keychain, caPath)

	case "linux":
		switch {
		case commandExists("update-ca-certificates"):
			dest := "/usr/local/share/ca-certificates/aor-ca.crt"
			if err := runInteractive("sudo", "cp", caPath, dest); err != nil {
				return err
			}
			return runInteractive("sudo", "update-ca-certificates")
		case commandExists("update-ca-trust"):
			dest := "/etc/pki/ca-trust/source/anchors/aor-ca.pem"
			if err := runInteractive("sudo", "cp", caPath, dest); err != nil {
				return err
			}
			return runInteractive("sudo", "update-ca-trust")
		default:
			return fmt.Errorf("no supported CA trust tool found (looked for update-ca-certificates, update-ca-trust) — install %s into your distro's trust store manually", caPath)
		}

	case "windows":
		return runInteractive("certutil", "-addstore", "-user", "Root", caPath)

	default:
		return fmt.Errorf("unsupported OS %q — install %s into your trust store manually", runtime.GOOS, caPath)
	}
}

func uninstallCA(caPath string) error {
	switch runtime.GOOS {
	case "darwin":
		return runInteractive("security", "remove-trusted-cert", "-d", caPath)

	case "linux":
		switch {
		case commandExists("update-ca-certificates"):
			dest := "/usr/local/share/ca-certificates/aor-ca.crt"
			if err := runInteractive("sudo", "rm", "-f", dest); err != nil {
				return err
			}
			return runInteractive("sudo", "update-ca-certificates", "--fresh")
		case commandExists("update-ca-trust"):
			dest := "/etc/pki/ca-trust/source/anchors/aor-ca.pem"
			if err := runInteractive("sudo", "rm", "-f", dest); err != nil {
				return err
			}
			return runInteractive("sudo", "update-ca-trust")
		default:
			return fmt.Errorf("no supported CA trust tool found — remove the AgentOnRails CA from your distro's trust store manually")
		}

	case "windows":
		return runInteractive("certutil", "-delstore", "-user", "Root", "AgentOnRails Local CA")

	default:
		return fmt.Errorf("unsupported OS %q — remove the AgentOnRails CA from your trust store manually", runtime.GOOS)
	}
}

func loginKeychainPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db"), nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func runInteractive(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v: %w", name, args, err)
	}
	return nil
}

func init() {
	trustCmd.AddCommand(trustInstallCmd, trustUninstallCmd)
	Root.AddCommand(trustCmd)
}
