package main

import (
	"flag"
	"os"
	"path/filepath"
)

// Config holds every runtime knob for the protocol lab.
type Config struct {
	ControlAddr string
	DemoAddr    string
	DataDir     string
	CertFile    string
	KeyFile     string
	StartTLS    bool
	DemoMode    string
	MaxSessions int
	OpenBrowser bool
}

// ParseConfig reads command line flags. Defaults keep the old ports and
// bind only to loopback.
func ParseConfig() Config {
	cfg := Config{}
	home, err := os.UserConfigDir()
	if err != nil || home == "" {
		home = "."
	}
	flag.StringVar(&cfg.ControlAddr, "control", "127.0.0.1:19527", "control plane (UI/API) address")
	flag.StringVar(&cfg.DemoAddr, "demo", "127.0.0.1:9527", "demo protocol address")
	flag.StringVar(&cfg.DataDir, "data-dir", filepath.Join(home, "tcpscope"), "directory for the generated certificate")
	flag.StringVar(&cfg.CertFile, "cert", "", "optional certificate PEM path (overrides generated cert)")
	flag.StringVar(&cfg.KeyFile, "key", "", "optional private key PEM path")
	flag.BoolVar(&cfg.StartTLS, "tls", false, "start the demo listener with TLS enabled")
	flag.StringVar(&cfg.DemoMode, "demo-mode", "stack", "demo mode: stack (HTTP/WS/TLS) or legacy (raw TCP echo)")
	flag.IntVar(&cfg.MaxSessions, "max-sessions", 64, "maximum concurrent lab sessions")
	flag.BoolVar(&cfg.OpenBrowser, "open", true, "open the console in the default browser")
	flag.Parse()
	if cfg.MaxSessions < 1 {
		cfg.MaxSessions = 1
	}
	return cfg
}
