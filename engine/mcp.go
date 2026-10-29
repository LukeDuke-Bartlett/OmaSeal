package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// runMCP starts a Model Context Protocol server over stdio. It exposes the
// safe operations of the keyring as tools that agents can call. Secrets are
// never logged to stdout; stdout is reserved for JSON-RPC traffic.
func runMCP() {
	// stdout is reserved for JSON-RPC; logging already goes to stderr + file.
	scanner := bufio.NewScanner(os.Stdin)
	// Secrets (PEM bundles, service-account JSON) can exceed the 64KB default.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		resp := handleMCPMessage([]byte(line))
		if resp != nil {
			if err := enc.Encode(resp); err != nil {
				log.Printf("omaseal mcp: encode error: %v", err)
				return
			}
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		log.Printf("omaseal mcp: scanner error: %v", err)
	}
}

type mcpMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func newMCPError(code int, msg string) *mcpError {
	return &mcpError{Code: code, Message: msg}
}

func handleMCPMessage(raw []byte) *mcpResponse {
	var msg mcpMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return &mcpResponse{JSONRPC: "2.0", Error: newMCPError(-32700, "parse error")}
	}
	if msg.JSONRPC != "2.0" {
		return nil
	}

	// Notifications have no id and must never receive a response frame.
	if len(msg.ID) == 0 {
		return nil
	}
	switch msg.Method {
	case "initialize":
		return &mcpResponse{JSONRPC: "2.0", ID: msg.ID, Result: initMCPResult()}
	case "notifications/initialized":
		return nil
	case "ping":
		return &mcpResponse{JSONRPC: "2.0", ID: msg.ID, Result: map[string]any{}}
	case "tools/list":
		return &mcpResponse{JSONRPC: "2.0", ID: msg.ID, Result: mcpToolsResult}
	case "tools/call":
		var req mcpToolCall
		if err := json.Unmarshal(msg.Params, &req); err != nil {
			return &mcpResponse{JSONRPC: "2.0", ID: msg.ID, Error: newMCPError(-32602, "invalid params: "+err.Error())}
		}
		var p struct {
			Service string `json:"service"`
			Account string `json:"account"`
		}
		_ = json.Unmarshal(req.Arguments, &p)
		WriteLog("mcp tool: %s %s/%s", req.Name, p.Service, p.Account)
		req.startedAt = time.Now()
		resp := callMCPTool(req)
		resp.ID = msg.ID
		return resp
	default:
		return &mcpResponse{JSONRPC: "2.0", ID: msg.ID, Error: newMCPError(-32601, "method not found")}
	}
}

// mcpInstructions tells every connecting agent how OmaSeal should be used.
// It is returned in the initialize result so agents pick up the convention
// automatically, without the user having to write rules files.
const mcpInstructions = `OmaSeal is the system keyring on this Omarchy machine — think macOS Keychain for agents. ` +
	`When you need an API key, token, password, or other credential, call omaseal_resolve or omaseal_get with a ` +
	`service and account name (for example service="openrouter", account="default") instead of asking the user to ` +
	`paste secrets, reading .env files, or grepping dotfiles. When the user gives you a new credential to keep, ` +
	`store it with omaseal_set — never write secrets to files, dotfiles, shell arguments, or logs. ` +
	`When the USER needs to type or paste the credential, call omaseal_ask_save instead: it opens a masked ` +
	`system dialog, stores the answer, and the value never passes through your context. ` +
	`omaseal_list returns service/account metadata only (no values) and is safe for discovering what is stored. ` +
	`A stored omaseal://<service>/<account> reference may be passed verbatim in the service field of any tool. ` +
	`omaseal_stats reports per-secret access counts so you can find the credential the user means by its usage. ` +
	`When you discover a stored credential has leaked (printed to a log, committed to a file, left in a transcript), ` +
	`call omaseal_flag to mark it for rotation — every later read then carries a warning until it is replaced with omaseal_set. ` +
	`Per-secret access is governed by ~/.config/omaseal/ai-manifest.txt: ALLOW secrets read freely, ` +
	`ASK secrets need an unlocked session, DENY secrets are refused with code manifest_denied. ` +
	`If a call fails with code agent_unauthorized, tell the user to run "omaseal agent unlock"; ` +
	`for manifest_denied, do not retry — suggest the user review the rule with "omaseal manifest check <service> <account>"; ` +
	`for not_found, suggest "omaseal set <service> <account>" or omaseal_set.`

func initMCPResult() map[string]any {
	return map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]string{
			"name":    "omaseal",
			"version": version,
		},
		"instructions": mcpInstructions,
	}
}

var mcpToolsResult = map[string]any{
	"tools": []map[string]any{
		{
			"name":        "omaseal_get",
			"description": "Retrieve a stored secret from the local OmaSeal keyring. Use this when the user or a provider needs the value at runtime. Does not fall back to 1Password/Bitwarden and does not trigger a fingerprint gate. A stored omaseal://<service>/<account> reference may be passed verbatim in the service field.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"service": map[string]string{"type": "string"}, "account": map[string]string{"type": "string"}},
				"required":   []string{"service"},
			},
		},
		{
			"name":        "omaseal_resolve",
			"description": "Resolve a secret from local keyring, 1Password, or Bitwarden. Caches the result locally. Safe for noninteractive calls. A stored omaseal://<service>/<account> reference may be passed verbatim in the service field.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"service": map[string]string{"type": "string"}, "account": map[string]string{"type": "string"}},
				"required":   []string{"service"},
			},
		},
		{
			"name":        "omaseal_set",
			"description": "Store a secret in the local OmaSeal keyring. Use this as the default, safe place to store API keys and credentials for the user. The secret is passed in this tool call; it is never written to a shell command or dotfile.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"service": map[string]string{"type": "string"},
					"account": map[string]string{"type": "string"},
					"secret":  map[string]string{"type": "string"},
				},
				"required": []string{"service", "secret"},
			},
		},
		{
			"name":        "omaseal_ask_save",
			"description": "Ask the USER to enter a secret via a masked system dialog, then store it under service/account. Use this whenever the human must supply the credential — the value is collected by the OS dialog and never passes through your context or this tool call. Returns ok on save; cancelled/locked errors tell you what the user should do next.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"service":     map[string]string{"type": "string"},
					"account":     map[string]string{"type": "string"},
					"description": map[string]string{"type": "string"},
				},
				"required": []string{"service"},
			},
		},
		{
			"name":        "omaseal_delete",
			"description": "Delete a secret from the local keyring by service and account. A stored omaseal://<service>/<account> reference may be passed verbatim in the service field.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"service": map[string]string{"type": "string"}, "account": map[string]string{"type": "string"}},
				"required":   []string{"service"},
			},
		},
		{
			"name":        "omaseal_list",
			"description": "List secrets in the local keyring. Optionally filter by service and sort by usage. Returns metadata only; no secret values. Each item carries access_count, last_accessed, and owned (true when OmaSeal wrote it).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"service": map[string]string{"type": "string"},
					"sort":    map[string]any{"type": "string", "enum": []string{"used", "recent", "name"}},
				},
				"required": []string{},
			},
		},
		{
			"name":        "omaseal_flag",
			"description": "Mark a stored secret for rotation and attach a note. Use when you discover a credential has leaked — printed to a log, committed to a repo or file, left in a transcript, or exposed another way. The secret still reads normally, but every later get/resolve/list surface carries a warning until the value is replaced with omaseal_set (which clears the flag) or the flag is removed with omaseal_unflag.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"service": map[string]string{"type": "string"},
					"account": map[string]string{"type": "string"},
					"reason":  map[string]string{"type": "string"},
				},
				"required": []string{"service"},
			},
		},
		{
			"name":        "omaseal_unflag",
			"description": "Clear the rotation flag on a stored secret without changing its value. Use when the flag was set in error or the credential was rotated outside omaseal.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"service": map[string]string{"type": "string"}, "account": map[string]string{"type": "string"}},
				"required":   []string{"service"},
			},
		},
		{
			"name":        "omaseal_stats",
			"description": "Report keyring usage analytics: total accesses and per-secret access counts/last-accessed times, most-used first. Metadata only; no secret values.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
				"required":   []string{},
			},
		},
		{
			"name":        "omaseal_status",
			"description": "Report the agent trust policy and session state (mode, unlock status, expiry, keep-alive). Read-only and non-secret; unlocking stays a human-only action.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
				"required":   []string{},
			},
		},
	},
}

type mcpToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	startedAt time.Time
}

type mcpToolCallResponse struct {
	Content []map[string]any `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

func toolOperation(name string) string {
	switch name {
	case "omaseal_get":
		return "get"
	case "omaseal_resolve":
		return "resolve"
	case "omaseal_set", "omaseal_ask_save":
		return "set"
	case "omaseal_delete":
		return "delete"
	case "omaseal_flag", "omaseal_unflag":
		return "set"
	case "omaseal_list", "omaseal_stats":
		return "list"
	}
	return ""
}

// checkManifestPolicy enforces the per-secret AI access manifest on agent
// reads and writes. DENY rejects outright; ASK requires an unlocked session
// even when the global agent mode is open; ALLOW proceeds. A missing or
// empty manifest applies no per-secret policy.
func checkManifestPolicy(service, account string) error {
	m, err := LoadManifest()
	if err != nil {
		return newError("manifest_error", "omaseal manifest",
			fmt.Errorf("AI manifest unreadable; refusing agent access: %w", err))
	}
	if m == nil || len(m.Rules) == 0 {
		return nil
	}
	policy, desc := m.CheckPolicy(service, account)
	switch policy {
	case PolicyDeny:
		return newError("manifest_denied", "omaseal manifest check "+service+" "+account,
			fmt.Errorf("AI manifest denies agent access to %s/%s (%s)", service, account, desc))
	case PolicyAsk:
		p, _ := loadAgentPolicy()
		if !agentSessionActive(p) {
			return newError("agent_unauthorized", "omaseal agent unlock",
				fmt.Errorf("manifest requires confirmation for %s/%s (%s)", service, account, desc))
		}
	}
	return nil
}

// loadManifestClosed loads the AI manifest for enumeration filtering. A
// missing or empty manifest denies nothing; an unreadable manifest fails
// closed — callers surface the error rather than enumerate secrets they
// cannot filter correctly.
func loadManifestClosed() (*Manifest, error) {
	m, err := LoadManifest()
	if err != nil {
		return nil, newError("manifest_error", "omaseal manifest",
			fmt.Errorf("AI manifest unreadable; refusing agent access: %w", err))
	}
	return m, nil
}

// manifestDenies reports whether the manifest denies a specific credential,
// evaluating pattern rules (including wildcard forms) per item.
func manifestDenies(m *Manifest, service, account string) bool {
	if m == nil {
		return false
	}
	policy, _ := m.CheckPolicy(service, account)
	return policy == PolicyDeny
}

// manifestDeniesPayload evaluates a raw "service/account" log payload. When
// a name contains "/" the split point is ambiguous; a DENY on any valid
// decomposition hides the entry — over-hiding a stat row is cosmetic, while
// under-hiding leaks a denied credential's existence.
func manifestDeniesPayload(m *Manifest, payload string) bool {
	if m == nil {
		return false
	}
	for i := 0; i < len(payload); i++ {
		if payload[i] == '/' && manifestDenies(m, payload[:i], payload[i+1:]) {
			return true
		}
	}
	return false
}

func callMCPTool(req mcpToolCall) *mcpResponse {
	r := mcpToolCallResponse{Content: []map[string]any{}}

	op := toolOperation(req.Name)
	if op != "" {
		if err := CheckAgentOperation(op); err != nil {
			return toolErrorResp(req, err)
		}
	}

	switch req.Name {
	case "omaseal_get":
		var a struct {
			Service string `json:"service"`
			Account string `json:"account"`
		}
		if err := json.Unmarshal(req.Arguments, &a); err != nil {
			return errResp(req, err)
		}
		service, account, err := refAwareCredentials(a.Service, a.Account, false)
		if err != nil {
			return toolErrorResp(req, err)
		}
		if err := checkManifestPolicy(service, account); err != nil {
			return toolErrorResp(req, err)
		}
		v, err := storeGet(service, account)
		if err != nil {
			return toolErrorResp(req, err)
		}
		WriteLog("access %s/%s", service, account)
		r.Content = append(r.Content, map[string]any{"type": "text", "text": v})
		if w := rotationWarning(service, account); w != "" {
			r.Content = append(r.Content, map[string]any{"type": "text", "text": w})
		}

	case "omaseal_resolve":
		var a struct {
			Service string `json:"service"`
			Account string `json:"account"`
		}
		if err := json.Unmarshal(req.Arguments, &a); err != nil {
			return errResp(req, err)
		}
		service, account, err := refAwareCredentials(a.Service, a.Account, false)
		if err != nil {
			return toolErrorResp(req, err)
		}
		if err := checkManifestPolicy(service, account); err != nil {
			return toolErrorResp(req, err)
		}
		v, err := Resolve(context.Background(), service, account, true, false)
		if err != nil {
			return toolErrorResp(req, err)
		}
		WriteLog("access %s/%s", service, account)
		r.Content = append(r.Content, map[string]any{"type": "text", "text": v})
		if w := rotationWarning(service, account); w != "" {
			r.Content = append(r.Content, map[string]any{"type": "text", "text": w})
		}

	case "omaseal_set":
		var a struct {
			Service string `json:"service"`
			Account string `json:"account"`
			Secret  string `json:"secret"`
		}
		if err := json.Unmarshal(req.Arguments, &a); err != nil {
			return errResp(req, err)
		}
		// Writes are strict: new names must satisfy the shared charset so
		// stored entries stay reachable and promptable everywhere.
		service, account, err := refAwareCredentials(a.Service, a.Account, true)
		if err != nil {
			return toolErrorResp(req, err)
		}
		if err := checkManifestPolicy(service, account); err != nil {
			return toolErrorResp(req, err)
		}
		if err := storeSet(service, account, a.Secret); err != nil {
			return toolErrorResp(req, err)
		}
		// A stored new value completes the rotation — drop a stale flag.
		if err := UnflagRotation(service, account); err != nil {
			WriteLog("mcp set %s/%s: flag clear failed: %v", service, account, err)
			r.Content = append(r.Content, map[string]any{"type": "text", "text": fmt.Sprintf("warning: value stored but rotation flag still set: %v", err)})
		}
		r.Content = append(r.Content, map[string]any{"type": "text", "text": "ok"})

	case "omaseal_ask_save":
		var a struct {
			Service     string `json:"service"`
			Account     string `json:"account"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(req.Arguments, &a); err != nil {
			return errResp(req, err)
		}
		// Writes are strict, same as omaseal_set — the dialog stores under
		// this name, so it must satisfy the shared charset.
		service, account, err := refAwareCredentials(a.Service, a.Account, true)
		if err != nil {
			return toolErrorResp(req, err)
		}
		if err := checkManifestPolicy(service, account); err != nil {
			return toolErrorResp(req, err)
		}
		if err := askSave(context.Background(), service, account, a.Description); err != nil {
			return toolErrorResp(req, err)
		}
		WriteLog("ask-save %s/%s", service, account)
		r.Content = append(r.Content, map[string]any{"type": "text", "text": "ok"})

	case "omaseal_delete":
		var a struct {
			Service string `json:"service"`
			Account string `json:"account"`
		}
		if err := json.Unmarshal(req.Arguments, &a); err != nil {
			return errResp(req, err)
		}
		service, account, err := refAwareCredentials(a.Service, a.Account, false)
		if err != nil {
			return toolErrorResp(req, err)
		}
		if err := checkManifestPolicy(service, account); err != nil {
			return toolErrorResp(req, err)
		}
		if err := storeDelete(service, account); err != nil {
			return toolErrorResp(req, err)
		}
		r.Content = append(r.Content, map[string]any{"type": "text", "text": "ok"})

	case "omaseal_list":
		var a struct {
			Service string `json:"service"`
			Sort    string `json:"sort"`
		}
		if len(req.Arguments) > 0 {
			if err := json.Unmarshal(req.Arguments, &a); err != nil {
				return errResp(req, err)
			}
		}
		service, err := refAwareService(a.Service, false)
		if err != nil {
			return toolErrorResp(req, err)
		}
		items, err := listItems(service, a.Sort)
		if err != nil {
			return toolErrorResp(req, err)
		}
		if m, err := loadManifestClosed(); err != nil {
			return toolErrorResp(req, err)
		} else {
			visible := items[:0]
			for _, it := range items {
				if !manifestDenies(m, it.Service, it.Account) {
					visible = append(visible, it)
				}
			}
			items = visible
		}
		b, err := json.Marshal(items)
		if err != nil {
			return toolErrorResp(req, err)
		}
		r.Content = append(r.Content, map[string]any{"type": "text", "text": string(b)})

	case "omaseal_flag":
		var a struct {
			Service string `json:"service"`
			Account string `json:"account"`
			Reason  string `json:"reason"`
		}
		if err := json.Unmarshal(req.Arguments, &a); err != nil {
			return errResp(req, err)
		}
		service, account, err := refAwareCredentials(a.Service, a.Account, false)
		if err != nil {
			return toolErrorResp(req, err)
		}
		if err := checkManifestPolicy(service, account); err != nil {
			return toolErrorResp(req, err)
		}
		if err := FlagRotation(service, account, a.Reason, "agent"); err != nil {
			return toolErrorResp(req, err)
		}
		WriteLog("mcp flag %s/%s", service, account)
		r.Content = append(r.Content, map[string]any{"type": "text", "text": "ok"})

	case "omaseal_unflag":
		var a struct {
			Service string `json:"service"`
			Account string `json:"account"`
		}
		if err := json.Unmarshal(req.Arguments, &a); err != nil {
			return errResp(req, err)
		}
		service, account, err := refAwareCredentials(a.Service, a.Account, false)
		if err != nil {
			return toolErrorResp(req, err)
		}
		if err := checkManifestPolicy(service, account); err != nil {
			return toolErrorResp(req, err)
		}
		if err := UnflagRotation(service, account); err != nil {
			return toolErrorResp(req, err)
		}
		WriteLog("mcp unflag %s/%s", service, account)
		r.Content = append(r.Content, map[string]any{"type": "text", "text": "ok"})

	case "omaseal_stats":
		statsMap, err := ParseAccessLogs()
		if err != nil {
			return toolErrorResp(req, err)
		}
		if m, err := loadManifestClosed(); err != nil {
			return toolErrorResp(req, err)
		} else if m != nil {
			for k := range statsMap {
				if manifestDeniesPayload(m, k) {
					delete(statsMap, k)
				}
			}
		}
		report := BuildAnalyticsReport(statsMap)
		b, err := json.Marshal(report)
		if err != nil {
			return toolErrorResp(req, err)
		}
		r.Content = append(r.Content, map[string]any{"type": "text", "text": string(b)})

	case "omaseal_status":
		// Ungated: the status payload is non-secret and must stay readable
		// even while the agent policy is locked.
		status, err := agentStatusJSON()
		if err != nil {
			return toolErrorResp(req, err)
		}
		r.Content = append(r.Content, map[string]any{"type": "text", "text": status})

	default:
		return &mcpResponse{JSONRPC: "2.0", Error: newMCPError(-32602, "unknown tool: "+req.Name)}
	}
	return &mcpResponse{JSONRPC: "2.0", Result: r}
}

// logMCPFailure records a telemetry line for a failed tool call — the surface
// where agents experience errors and hangs. Successes already emit access
// lines; failures returned isError responses that left no trace.
func logMCPFailure(req mcpToolCall, err error) {
	var a struct {
		Service string `json:"service"`
		Account string `json:"account"`
	}
	_ = json.Unmarshal(req.Arguments, &a)
	target := a.Service
	if a.Account != "" {
		target += "/" + a.Account
	}
	start := req.startedAt
	if start.IsZero() {
		start = time.Now()
	}
	logOpResult("mcp-"+req.Name, target, start, err)
}

func errResp(req mcpToolCall, err error) *mcpResponse {
	logMCPFailure(req, err)
	return &mcpResponse{JSONRPC: "2.0", Error: newMCPError(-32602, "invalid arguments for "+req.Name+": "+err.Error())}
}

func toolErrorResp(req mcpToolCall, err error) *mcpResponse {
	logMCPFailure(req, err)
	text := err.Error()
	if code := codeFromError(err); code != "" {
		text = text + " (code: " + code + ", help: " + helpFromError(err) + ")"
	}
	return &mcpResponse{JSONRPC: "2.0", Result: map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": true,
	}}
}
