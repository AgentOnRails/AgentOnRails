package commands

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/agentOnRails/agent-on-rails/config"
)

func TestBuildRunEnv_ProxyVarsAlwaysSet(t *testing.T) {
	global := &config.GlobalConfig{Daemon: config.DaemonConfig{ListenAddr: "127.0.0.1"}}
	agent := &config.AgentConfig{AgentID: "my-agent", ProxyPort: 8402}

	env := buildRunEnv(global, agent)

	want := map[string]string{
		"HTTP_PROXY":  "http://127.0.0.1:8402",
		"HTTPS_PROXY": "http://127.0.0.1:8402",
		"http_proxy":  "http://127.0.0.1:8402",
		"https_proxy": "http://127.0.0.1:8402",
	}
	for k, v := range want {
		if !hasEnvEntry(env, k+"="+v) {
			t.Errorf("expected env to contain %s=%s, got %v", k, v, env)
		}
	}
}

func TestBuildRunEnv_DefaultsListenAddrWhenEmpty(t *testing.T) {
	global := &config.GlobalConfig{} // ListenAddr unset
	agent := &config.AgentConfig{AgentID: "my-agent", ProxyPort: 9000}

	env := buildRunEnv(global, agent)

	if !hasEnvEntry(env, "HTTP_PROXY=http://"+config.DefaultListenAddr+":9000") {
		t.Errorf("expected default listen addr in proxy URL, got %v", env)
	}
}

func TestBuildRunEnv_NoCAVarsWhenInterceptDisabled(t *testing.T) {
	global := &config.GlobalConfig{Daemon: config.DaemonConfig{ListenAddr: "127.0.0.1", HTTPSIntercept: false}}
	agent := &config.AgentConfig{AgentID: "my-agent", ProxyPort: 8402}

	env := buildRunEnv(global, agent)

	for _, k := range []string{"REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE"} {
		if hasEnvPrefix(env, k+"=") {
			t.Errorf("did not expect %s to be set when https_intercept is disabled", k)
		}
	}
}

func TestBuildRunEnv_CAVarsSetWhenInterceptEnabledAndCertExists(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "aor-ca.crt")
	if err := os.WriteFile(caPath, []byte("fake cert"), 0o644); err != nil {
		t.Fatal(err)
	}

	global := &config.GlobalConfig{Daemon: config.DaemonConfig{ListenAddr: "127.0.0.1", HTTPSIntercept: true, CADir: dir}}
	agent := &config.AgentConfig{AgentID: "my-agent", ProxyPort: 8402}

	env := buildRunEnv(global, agent)

	for _, k := range []string{"REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE"} {
		if !hasEnvEntry(env, k+"="+caPath) {
			t.Errorf("expected %s=%s in env, got %v", k, caPath, env)
		}
	}
}

func TestBuildRunEnv_NoCAVarsWhenCertMissing(t *testing.T) {
	dir := t.TempDir() // empty — no aor-ca.crt written

	global := &config.GlobalConfig{Daemon: config.DaemonConfig{ListenAddr: "127.0.0.1", HTTPSIntercept: true, CADir: dir}}
	agent := &config.AgentConfig{AgentID: "my-agent", ProxyPort: 8402}

	env := buildRunEnv(global, agent)

	for _, k := range []string{"REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE"} {
		if hasEnvPrefix(env, k+"=") {
			t.Errorf("did not expect %s to be set when the CA cert file doesn't exist yet", k)
		}
	}
}

func hasEnvEntry(env []string, entry string) bool {
	return slices.Contains(env, entry)
}

func hasEnvPrefix(env []string, prefix string) bool {
	return slices.ContainsFunc(env, func(e string) bool {
		return strings.HasPrefix(e, prefix)
	})
}
