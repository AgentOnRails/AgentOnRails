package e2e

// Agent-framework compatibility matrix — turns README's compatibility
// claims ("Any HTTP client that respects standard proxy env vars works —
// Python httpx/requests, Node fetch, curl, LangChain, CrewAI, etc.",
// README.md:120) into a tested guarantee instead of an assertion nobody
// re-checks. Every other e2e test in this package drives the proxy with
// Go's own net/http.Client — this file is the one place that drives it with
// real external processes instead, at the actual HTTP-proxy-protocol level
// (explicit proxy CONNECT/absolute-form requests) every proxy-aware client
// library speaks, regardless of language.
//
// Each client is optional: if its interpreter/binary isn't installed on the
// machine running the tests, that one subtest skips rather than fails — the
// point is "if you have curl/python/node, prove enforcement holds for it,"
// not "every CI runner must have every language installed."

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// clientCompat is one entry in the compatibility matrix: a real external
// process making one request through the daemon's transparent proxy using
// only that language's standard library (no third-party packages to
// install) — proxying at the plain HTTP absolute-form-request level, the
// same thing curl -x, Python's urllib.request.ProxyHandler, and Node's core
// http module going through a proxy host all do identically, and the same
// thing Go's own http.Client (already exercised by every other test in this
// package) does via Transport.Proxy.
type clientCompat struct {
	name    string
	binary  string
	command func(proxyAddr, targetURL string) *exec.Cmd
}

func pythonBinary() string {
	for _, name := range []string{"python3", "python"} {
		if _, err := exec.LookPath(name); err == nil {
			return name
		}
	}
	return "python3" // LookPath will fail again in the caller, producing a clear skip
}

var clientCompatMatrix = []clientCompat{
	{
		// -o/dev-null's spelling differs by OS (NUL vs /dev/null); instead
		// this leaves the body on stdout and puts the status code on its
		// own trailing line (\n%{http_code}) — the test reads only the
		// last line, so it works identically on Windows and Linux CI.
		name:   "curl",
		binary: "curl",
		command: func(proxyAddr, targetURL string) *exec.Cmd {
			return exec.Command("curl", "-s", "-w", "\n%{http_code}", "-x", "http://"+proxyAddr, targetURL)
		},
	},
	{
		name:   "python (stdlib urllib)",
		binary: pythonBinary(),
		command: func(proxyAddr, targetURL string) *exec.Cmd {
			// urllib raises HTTPError on any non-2xx status instead of
			// returning it like curl/requests/fetch do — caught here so a
			// real 403 (budget exhausted) prints as a status code, not a
			// stack trace this test would otherwise misread as a crash.
			script := fmt.Sprintf(`
import urllib.request, urllib.error
proxy = urllib.request.ProxyHandler({"http": "http://%s"})
opener = urllib.request.build_opener(proxy)
try:
    resp = opener.open(%q, timeout=10)
    print(resp.getcode())
except urllib.error.HTTPError as e:
    print(e.code)
`, proxyAddr, targetURL)
			return exec.Command(pythonBinary(), "-c", script)
		},
	},
	{
		name:   "node (stdlib http)",
		binary: "node",
		command: func(proxyAddr, targetURL string) *exec.Cmd {
			script := fmt.Sprintf(`
const http = require("http");
const [host, port] = %q.split(":");
const req = http.request({ host, port: Number(port), path: %q, method: "GET" }, (res) => {
  console.log(res.statusCode);
  res.resume();
});
req.on("error", (e) => { console.error(e); process.exit(1); });
req.end();
`, proxyAddr, targetURL)
			return exec.Command("node", "-e", script)
		},
	},
}

// TestClientCompatibility_EveryClientTypeGetsAPaidResponse drives one real
// request through the running proxy from each available external client and
// confirms it gets back the same final 200 Go's own http.Client already
// gets elsewhere in this package — proving the transparent-proxy payment
// negotiation (402 -> sign -> retry) is invisible to the calling client
// regardless of what language/library made the request, not just to Go's.
func TestClientCompatibility_EveryClientTypeGetsAPaidResponse(t *testing.T) {
	f := startDaemon(t, defaultOpts())

	ran := 0
	for _, c := range clientCompatMatrix {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if _, err := exec.LookPath(c.binary); err != nil {
				t.Skipf("%s not installed on this machine — skipping", c.binary)
			}
			ran++

			out, err := c.command(f.ProxyAddr, f.Upstream.URL+"/paid").CombinedOutput()
			if err != nil {
				t.Fatalf("%s: %v\noutput: %s", c.name, err, out)
			}
			if status := lastLine(out); !strings.Contains(status, "200") {
				t.Fatalf("%s: expected a 200 response through the proxy, got: %q (full output: %s)", c.name, status, out)
			}
		})
	}

	if ran == 0 {
		t.Skip("none of curl/python/node are installed on this machine — nothing to compare against Go's own http.Client")
	}

	txns := f.recentTxns(t)
	if len(txns) == 0 {
		t.Fatal("expected at least one audit record from the client(s) above — none reached the daemon's real x402 pipeline")
	}
}

// TestClientCompatibility_BudgetEnforcedRegardlessOfWhichClientAsks proves
// budget enforcement isn't something only Go's own http.Client happens to
// trigger: it exhausts a tight daily budget via one client type, then
// confirms a DIFFERENT client type is blocked by the same budget state —
// enforcement lives in the daemon's policy engine, not in anything specific
// to whichever library is calling it.
func TestClientCompatibility_BudgetEnforcedRegardlessOfWhichClientAsks(t *testing.T) {
	available := make([]clientCompat, 0, len(clientCompatMatrix))
	for _, c := range clientCompatMatrix {
		if _, err := exec.LookPath(c.binary); err == nil {
			available = append(available, c)
		}
	}
	if len(available) < 2 {
		t.Skip("need at least 2 of curl/python/node installed to prove enforcement is shared across different clients")
	}

	f := startDaemonWithUpstream(t, daemonOptions{
		PerCallMaxUSD: "0.01",
		DailyLimitUSD: "0.01", // exhausted by exactly one $0.01 payment
		EndpointMode:  "open",
		SkipPreVerify: true,
	}, startMockUpstream(t))

	spender, blockee := available[0], available[1]

	spendOut, err := spender.command(f.ProxyAddr, f.Upstream.URL+"/paid").CombinedOutput()
	if err != nil {
		t.Fatalf("%s (spending the budget): %v\noutput: %s", spender.name, err, spendOut)
	}
	if status := lastLine(spendOut); !strings.Contains(status, "200") {
		t.Fatalf("%s: expected 200 for the budget-exhausting payment, got: %q (full output: %s)", spender.name, status, spendOut)
	}

	blockOut, err := blockee.command(f.ProxyAddr, f.Upstream.URL+"/paid").CombinedOutput()
	if err != nil {
		t.Fatalf("%s (expected to be blocked): %v\noutput: %s", blockee.name, err, blockOut)
	}
	if status := lastLine(blockOut); strings.Contains(status, "200") {
		t.Fatalf("%s: expected a non-200 (budget exhausted) response, got: %q (full output: %s)", blockee.name, status, blockOut)
	}
}

// lastLine returns the last non-empty line of out — used to read the status
// code each client command prints on its own trailing line, ignoring any
// response body curl also writes to stdout ahead of it.
func lastLine(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
