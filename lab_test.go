package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCertSANsAndPersistence(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir, MaxSessions: 4}
	mgr, err := NewTLSManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	info := mgr.CertInfo()
	joined := strings.Join(info.SANs, ",")
	for _, want := range []string{"127.0.0.1", "::1", "localhost"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("SAN %q missing from %q", want, joined)
		}
	}
	if len(info.SHA256) != 64 {
		t.Fatalf("bad fingerprint %q", info.SHA256)
	}
	if !fileExists(dir + "/cert.pem") || !fileExists(dir + "/key.pem") {
		t.Fatal("certificate files were not persisted")
	}
	mgr2, err := NewTLSManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if mgr2.CertInfo().SHA256 != info.SHA256 {
		t.Fatal("reloading the certificate changed the fingerprint")
	}
}

func TestWSFrameRoundTrip(t *testing.T) {
	opts := defaultWSOptions()
	opts.ReadTimeout = 2 * time.Second
	opts.WriteTimeout = 2 * time.Second
	a, b := net.Pipe()
	server := &WSConn{conn: a, br: bufio.NewReader(a), bw: bufio.NewWriter(a), role: "server", opts: opts}
	client := &WSConn{conn: b, br: bufio.NewReader(b), bw: bufio.NewWriter(b), role: "client", opts: opts}
	defer a.Close()
	defer b.Close()

	cases := []struct {
		op   byte
		data []byte
	}{
		{wsOpText, []byte("hello ws")},
		{wsOpBinary, bytes.Repeat([]byte{0x01, 0x02, 0x03}, 120)},
	}
	for _, tc := range cases {
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = client.WriteMessage(tc.op, tc.data)
		}()
		op, payload, err := server.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		<-done
		if op != tc.op || !bytes.Equal(payload, tc.data) {
			t.Fatalf("round trip mismatch: op=%d len=%d", op, len(payload))
		}
	}
}

func TestEventSanitize(t *testing.T) {
	ev := Event{Layer: "http", Plaintext: map[string]any{"body": "secret"}}
	if ev.Sanitize(false).Plaintext != nil {
		t.Fatal("plaintext must be stripped when reveal is false")
	}
	if ev.Sanitize(true).Plaintext["body"] != "secret" {
		t.Fatal("plaintext must survive when reveal is true")
	}
}

func TestSessionRegistryCap(t *testing.T) {
	r := NewSessionRegistry(2)
	r.New("http", "plain", "l", "r")
	r.New("http", "plain", "l", "r")
	r.New("http", "plain", "l", "r")
	if got := r.Count(); got != 2 {
		t.Fatalf("registry cap: got %d want 2", got)
	}
}

func TestLabHTTPAndTLS(t *testing.T) {
	cfg := Config{
		ControlAddr: "127.0.0.1:0",
		DemoAddr:    "127.0.0.1:0",
		DataDir:     t.TempDir(),
		DemoMode:    "stack",
		MaxSessions: 8,
	}
	lab, err := NewLab(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := lab.startDemo(false); err != nil {
		t.Fatal(err)
	}
	if err := lab.startControl(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer lab.Shutdown(ctx)

	plainURL := "http://" + lab.demoAddr() + "/demo/hello"
	resp, err := http.Get(plainURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "hello") {
		t.Fatalf("plain hello failed: %d %s", resp.StatusCode, body)
	}

	if err := lab.switchTLS(true); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: lab.tlsMgr.ClientConfig()}, Timeout: 5 * time.Second}
	tlsURL := "https://" + lab.demoAddr() + "/demo/hello"
	resp, err = client.Get(tlsURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "hello") {
		t.Fatalf("tls hello failed: %d %s", resp.StatusCode, body)
	}
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3, got %+v", resp.TLS)
	}

	if err := lab.switchTLS(false); err != nil {
		t.Fatal(err)
	}
	resp, err = http.Get("http://" + lab.demoAddr() + "/demo/hello")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("switch back to plain failed: %d", resp.StatusCode)
	}
}

func TestRevealGateOverControlPlane(t *testing.T) {
	cfg := Config{
		ControlAddr: "127.0.0.1:0",
		DemoAddr:    "127.0.0.1:0",
		DataDir:     t.TempDir(),
		DemoMode:    "stack",
		MaxSessions: 8,
	}
	lab, err := NewLab(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := lab.startDemo(false); err != nil {
		t.Fatal(err)
	}
	if err := lab.startControl(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer lab.Shutdown(ctx)
	if err := lab.switchTLS(true); err != nil {
		t.Fatal(err)
	}
	control := "http://" + lab.controlAddr() + "/api/demo/http"

	post := func(reveal bool) map[string]any {
		payload, _ := json.Marshal(map[string]any{
			"method": "GET", "path": "/demo/hello", "reveal": reveal,
		})
		resp, err := http.Post(control, "application/json", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	masked := post(false)
	if masked["encrypted"] != true || masked["masked"] != true {
		t.Fatalf("expected masked TLS response, got %#v", masked)
	}
	serialized, _ := json.Marshal(masked)
	if strings.Contains(string(serialized), "hello") && strings.Contains(string(serialized), "\"body\"") {
		t.Fatal("masked response leaked the body")
	}

	revealed := post(true)
	if revealed["masked"] == true {
		t.Fatalf("revealed response was masked: %#v", revealed)
	}
	serialized, _ = json.Marshal(revealed)
	if !strings.Contains(string(serialized), "hello") {
		t.Fatal("revealed response did not include plaintext")
	}
}
