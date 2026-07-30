package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentOnRails/agent-on-rails/config"
)

func TestResolveCACertPath_DefaultsWhenNoConfig(t *testing.T) {
	orig := globalConfigPath
	globalConfigPath = filepath.Join(t.TempDir(), "does-not-exist.yaml")
	t.Cleanup(func() { globalConfigPath = orig })

	got, err := resolveCACertPath()
	if err != nil {
		t.Fatalf("resolveCACertPath: %v", err)
	}
	want := filepath.Join(config.ExpandHomePath("~/.aor/ca"), "aor-ca.crt")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveCACertPath_UsesConfiguredCADir(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "aor.yaml")
	caDir := filepath.ToSlash(filepath.Join(dir, "custom-ca"))
	yamlContent := fmt.Sprintf("daemon:\n  ca_dir: %q\n", caDir)
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0600); err != nil {
		t.Fatal(err)
	}

	orig := globalConfigPath
	globalConfigPath = cfgPath
	t.Cleanup(func() { globalConfigPath = orig })

	got, err := resolveCACertPath()
	if err != nil {
		t.Fatalf("resolveCACertPath: %v", err)
	}
	want := filepath.Join(dir, "custom-ca", "aor-ca.crt")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCommandExists_FindsARealCommand(t *testing.T) {
	// go is virtually guaranteed to be on PATH in this test's own
	// environment (it's what's running the test).
	if !commandExists("go") {
		t.Error("expected commandExists(\"go\") to be true")
	}
}

func TestCommandExists_RejectsANonsenseName(t *testing.T) {
	if commandExists("definitely-not-a-real-command-xyz123") {
		t.Error("expected commandExists to be false for a nonexistent command")
	}
}

func TestLoginKeychainPath_ReturnsPathUnderHomeLibraryKeychains(t *testing.T) {
	got, err := loginKeychainPath()
	if err != nil {
		t.Fatalf("loginKeychainPath: %v", err)
	}
	if filepath.Base(got) != "login.keychain-db" {
		t.Errorf("got %q, want a path ending in login.keychain-db", got)
	}
}
