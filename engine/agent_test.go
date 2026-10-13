package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// setupAgentEnv points the policy (XDG_CONFIG_HOME) and session
// (XDG_RUNTIME_DIR) stores at per-test temp dirs.
func setupAgentEnv(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
}

func askPolicy(t *testing.T, keepAlive bool) {
	t.Helper()
	if err := saveAgentPolicy(AgentPolicy{Mode: "ask", SessionMinutes: 15, KeepAlive: keepAlive}); err != nil {
		t.Fatalf("save policy: %v", err)
	}
}

func TestKeepAliveSlidesExpiry(t *testing.T) {
	setupAgentEnv(t)
	askPolicy(t, true)

	soon := time.Now().UTC().Add(time.Minute)
	if err := writeSessionExpiry(soon); err != nil {
		t.Fatalf("write session: %v", err)
	}
	if err := CheckAgentOperation("list"); err != nil {
		t.Fatalf("check op: %v", err)
	}
	got, ok := readSessionExpiry()
	if !ok {
		t.Fatal("session file missing after op")
	}
	if got.Before(time.Now().UTC().Add(14 * time.Minute)) {
		t.Fatalf("keep-alive did not slide expiry: still %s", got)
	}
}

func TestFixedExpiryWithoutKeepAlive(t *testing.T) {
	setupAgentEnv(t)
	askPolicy(t, false)

	soon := time.Now().UTC().Add(time.Minute)
	if err := writeSessionExpiry(soon); err != nil {
		t.Fatalf("write session: %v", err)
	}
	if err := CheckAgentOperation("list"); err != nil {
		t.Fatalf("check op: %v", err)
	}
	got, ok := readSessionExpiry()
	if !ok {
		t.Fatal("session file missing after op")
	}
	if !got.Equal(soon.Truncate(time.Second)) {
		t.Fatalf("expiry moved without keep-alive: %s -> %s", soon, got)
	}
}

func TestKeepAliveDoesNotReviveExpiredSession(t *testing.T) {
	setupAgentEnv(t)
	askPolicy(t, true)

	past := time.Now().UTC().Add(-time.Minute)
	if err := writeSessionExpiry(past); err != nil {
		t.Fatalf("write session: %v", err)
	}
	err := CheckAgentOperation("list")
	if err == nil || !strings.Contains(err.Error(), "unlock") {
		t.Fatalf("expected unauthorized error, got %v", err)
	}
}

func TestRenewalDoesNotResurrectLockedSession(t *testing.T) {
	setupAgentEnv(t)
	askPolicy(t, true)

	// Simulate `agent lock` removing the file between an op's session read
	// and its keep-alive renewal: the renewal must not recreate it.
	renewal := time.Now().UTC().Add(15 * time.Minute)
	if err := renewSessionExpiry(renewal); err == nil {
		t.Fatal("renewal created a session file that never existed")
	}
	if _, ok := readSessionExpiry(); ok {
		t.Fatal("session resurrected after removal")
	}
}

func TestAgentStatusJSONContract(t *testing.T) {
	setupAgentEnv(t)
	askPolicy(t, true)

	s, err := agentStatusJSON()
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		t.Fatal(err)
	}
	if d["mode"] != "ask" || d["keep_alive"] != true || d["session_active"] != false {
		t.Fatalf("bad status: %s", s)
	}
	if _, ok := d["fprintd_available"]; !ok {
		t.Fatal("ask mode must report fprintd_available")
	}
	if a, ok := d["agents"].([]any); !ok || a == nil {
		t.Fatalf("agents must be an array, got %T %v", d["agents"], d["agents"])
	}
	if _, ok := d["session_expires"]; ok {
		t.Fatal("session_expires must be absent without an active session")
	}
}

// The panel keys its unlock UX off `backend` — it must reflect the live
// store, not a config re-read.
func TestAgentStatusJSONBackend(t *testing.T) {
	setupAgentEnv(t)
	askPolicy(t, false)

	oldStore := currentStore
	t.Cleanup(func() { currentStore = oldStore })

	currentStore = ssStore{}
	s, err := agentStatusJSON()
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		t.Fatal(err)
	}
	if d["backend"] != "secretservice" {
		t.Fatalf("backend = %v, want secretservice", d["backend"])
	}

	_, dir := nativeTestStore(t)
	currentStore = newNativeStoreAt(dir, t.TempDir())
	s, err = agentStatusJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		t.Fatal(err)
	}
	if d["backend"] != "native" {
		t.Fatalf("backend = %v, want native", d["backend"])
	}
}

func TestSetAgentModePreservesPolicy(t *testing.T) {
	setupAgentEnv(t)
	if err := saveAgentPolicy(AgentPolicy{
		Mode: "ask", SessionMinutes: 15, KeepAlive: true,
		PrimaryAgent: "claude", Agents: []string{"claude", "devin"},
	}); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	if err := SetAgentMode("lock", 0, false); err != nil {
		t.Fatalf("set mode: %v", err)
	}
	p, err := loadAgentPolicy()
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if p.Mode != "lock" || !p.KeepAlive || p.PrimaryAgent != "claude" || len(p.Agents) != 2 {
		t.Fatalf("mode change clobbered policy: %+v", p)
	}
}

// Missing policy file must default to "ask" — never "open". Regression test
// for the marketplace security finding: a fresh install authorized every MCP
// operation with no user grant.
func TestDefaultPolicyIsAskNotOpen(t *testing.T) {
	setupAgentEnv(t) // no policy file written

	p, err := loadAgentPolicy()
	if err != nil {
		t.Fatalf("loadAgentPolicy: %v", err)
	}
	if p.Mode != "ask" {
		t.Fatalf("missing policy must default to ask, got %q", p.Mode)
	}
	if err := CheckAgentOperation("get"); err == nil {
		t.Fatal("agent ops must be denied without unlock on a fresh install")
	}
}

// An invalid mode in a present policy file must also fail closed.
func TestInvalidModeFailsClosed(t *testing.T) {
	setupAgentEnv(t)
	if err := saveAgentPolicy(AgentPolicy{Mode: "bogus", SessionMinutes: 15}); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	p, err := loadAgentPolicy()
	if err != nil {
		t.Fatalf("loadAgentPolicy: %v", err)
	}
	if p.Mode != "ask" {
		t.Fatalf("invalid mode must resolve to ask, got %q", p.Mode)
	}
}
