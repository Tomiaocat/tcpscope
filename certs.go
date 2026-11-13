package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CertInfo is the public description of the local certificate.
type CertInfo struct {
	Subject   string   `json:"subject"`
	SANs      []string `json:"sans"`
	SHA256    string   `json:"sha256"`
	NotBefore string   `json:"notBefore"`
	NotAfter  string   `json:"notAfter"`
	Source    string   `json:"source"`
}

// TLSInfo is the negotiated connection state shown in the UI.
type TLSInfo struct {
	Version    string    `json:"version"`
	Cipher     string    `json:"cipher"`
	ALPN       string    `json:"alpn"`
	ServerName string    `json:"serverName"`
	Verified   bool      `json:"verified"`
	Cert       *CertInfo `json:"cert,omitempty"`
}

// TLSManager owns the certificate and the on/off state. The actual listener
// rebinding lives in the App so this type stays free of network lifecycle.
type TLSManager struct {
	mu        sync.RWMutex
	enabled   bool
	state     string
	cert      tls.Certificate
	certPEM   []byte
	info      CertInfo
	serverCfg *tls.Config
	clientCfg *tls.Config
}

func NewTLSManager(cfg Config) (*TLSManager, error) {
	cert, certPEM, info, err := loadOrCreateCert(cfg)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, fmt.Errorf("certificate PEM could not be added to the trust pool")
	}
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	clientCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	return &TLSManager{
		enabled:   false,
		state:     "off",
		cert:      cert,
		certPEM:   certPEM,
		info:      info,
		serverCfg: serverCfg,
		clientCfg: clientCfg,
	}, nil
}

func (m *TLSManager) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

func (m *TLSManager) State() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *TLSManager) SetEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = enabled
	if enabled {
		m.state = "on"
	} else {
		m.state = "off"
	}
}

func (m *TLSManager) SetState(state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = state
}

func (m *TLSManager) ServerConfig() *tls.Config { return m.serverCfg }
func (m *TLSManager) ClientConfig() *tls.Config { return m.clientCfg }

func (m *TLSManager) CertInfo() CertInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.info
}

func (m *TLSManager) CertPEM() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]byte, len(m.certPEM))
	copy(out, m.certPEM)
	return out
}

// InfoFromState converts a tls.ConnectionState into the UI shape. When
// serverSide is true there is usually no peer certificate, so we report our
// own certificate instead.
func (m *TLSManager) InfoFromState(cs tls.ConnectionState, serverSide bool) *TLSInfo {
	if cs.Version == 0 {
		return nil
	}
	info := &TLSInfo{
		Version:    tlsVersionName(cs.Version),
		Cipher:     tls.CipherSuiteName(cs.CipherSuite),
		ALPN:       cs.NegotiatedProtocol,
		ServerName: cs.ServerName,
		Verified:   len(cs.VerifiedChains) > 0,
	}
	if serverSide || len(cs.PeerCertificates) == 0 {
		cert := m.CertInfo()
		info.Cert = &cert
	} else {
		info.Cert = certInfoFromX509(cs.PeerCertificates[0], "peer")
	}
	return info
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}

func certInfoFromX509(c *x509.Certificate, source string) *CertInfo {
	if c == nil {
		return nil
	}
	sum := sha256.Sum256(c.Raw)
	sans := make([]string, 0, len(c.DNSNames)+len(c.IPAddresses))
	sans = append(sans, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	return &CertInfo{
		Subject:   c.Subject.String(),
		SANs:      sans,
		SHA256:    hex.EncodeToString(sum[:]),
		NotBefore: c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  c.NotAfter.UTC().Format(time.RFC3339),
		Source:    source,
	}
}

func loadOrCreateCert(cfg Config) (tls.Certificate, []byte, CertInfo, error) {
	certPath := cfg.CertFile
	keyPath := cfg.KeyFile
	if certPath == "" && keyPath == "" {
		certPath = filepath.Join(cfg.DataDir, "cert.pem")
		keyPath = filepath.Join(cfg.DataDir, "key.pem")
	}
	if certPath == "" || keyPath == "" {
		return tls.Certificate{}, nil, CertInfo{}, fmt.Errorf("both -cert and -key are required")
	}
	if fileExists(certPath) && fileExists(keyPath) {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, nil, CertInfo{}, fmt.Errorf("load certificate: %w", err)
		}
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return tls.Certificate{}, nil, CertInfo{}, err
		}
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		return cert, certPEM, *certInfoFromX509(leaf, "loaded"), nil
	}
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		return tls.Certificate{}, nil, CertInfo{}, fmt.Errorf("certificate or key file not found")
	}
	return generateCert(certPath, keyPath)
}

func generateCert(certPath, keyPath string) (tls.Certificate, []byte, CertInfo, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, CertInfo{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, CertInfo{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "tcpscope localhost"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, CertInfo{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, nil, CertInfo{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return tls.Certificate{}, nil, CertInfo{}, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, nil, CertInfo{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, nil, CertInfo{}, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, CertInfo{}, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return cert, certPEM, *certInfoFromX509(leaf, "generated"), nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
