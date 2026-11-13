package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var errSwitchBusy = errors.New("tls switch already in progress")

// Lab is the real protocol stack: plaintext control plane + switchable
// demo plane (HTTP/WS, optionally TLS).
type Lab struct {
	cfg      Config
	tlsMgr   *TLSManager
	sessions *SessionRegistry
	events   *EventBus

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	switchMu sync.Mutex
	demoMu   sync.RWMutex
	demo     *demoPlane

	controlSrv *http.Server
	controlLn  net.Listener

	wsMu      sync.Mutex
	wsClients map[string]*labWSClient

	controlWSMu sync.Mutex
	controlWS   map[*WSConn]struct{}

	helloCount atomic.Uint64
	startedAt  time.Time
}

type demoPlane struct {
	ln    net.Listener
	srv   *http.Server
	addr  string
	tlsOn bool
	done  chan struct{}
}

func NewLab(cfg Config) (*Lab, error) {
	tlsMgr, err := NewTLSManager(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.StartTLS {
		tlsMgr.SetEnabled(true)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Lab{
		cfg:       cfg,
		tlsMgr:    tlsMgr,
		sessions:  NewSessionRegistry(cfg.MaxSessions),
		events:    NewEventBus(2000),
		ctx:       ctx,
		cancel:    cancel,
		wsClients: make(map[string]*labWSClient),
		controlWS: make(map[*WSConn]struct{}),
		startedAt: time.Now(),
	}, nil
}

func (l *Lab) Run() error {
	if err := l.startDemo(l.tlsMgr.Enabled()); err != nil {
		return err
	}
	if err := l.startControl(); err != nil {
		l.stopDemo()
		return err
	}
	go l.runJanitor(l.ctx)

	scheme := "http"
	if l.tlsMgr.Enabled() {
		scheme = "https"
	}
	log.Printf("================================================================")
	log.Printf("tcpscope 协议实验室已就绪")
	log.Printf("控制台:   http://%s", l.controlAddr())
	log.Printf("演示面:   %s://%s  (TLS: %s)", scheme, l.demoAddr(), l.tlsMgr.State())
	log.Printf("证书:     %s", l.tlsMgr.CertInfo().Subject)
	log.Printf("================================================================")

	if l.cfg.OpenBrowser {
		go func() {
			time.Sleep(400 * time.Millisecond)
			openBrowser("http://" + l.controlAddr() + "/")
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case <-l.ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	l.Shutdown(shutdownCtx)
	return nil
}

func (l *Lab) Shutdown(ctx context.Context) {
	l.cancel()
	if l.controlSrv != nil {
		_ = l.controlSrv.Shutdown(ctx)
	}
	l.closeControlWS()
	l.stopDemo()
	l.closeAllWSClient()
	l.events.Close()
	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (l *Lab) startControl() error {
	ln, err := net.Listen("tcp", l.cfg.ControlAddr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           l.controlMux(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	l.controlLn = ln
	l.controlSrv = srv
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[control] serve: %v", err)
		}
	}()
	return nil
}

func (l *Lab) startDemo(tlsOn bool) error {
	raw, err := net.Listen("tcp", l.cfg.DemoAddr)
	if err != nil {
		return err
	}
	var ln net.Listener = raw
	if tlsOn {
		ln = &tlsRecordingListener{Listener: raw, lab: l}
	}
	srv := &http.Server{
		Handler:           l.demoMux(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		// A non-nil empty map disables the automatic HTTP/2 setup. HTTP/2
		// response writers cannot be hijacked, so WebSocket needs 1.1.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:     log.New(io.Discard, "", 0),
	}
	dp := &demoPlane{ln: ln, srv: srv, addr: raw.Addr().String(), tlsOn: tlsOn, done: make(chan struct{})}
	l.demoMu.Lock()
	l.demo = dp
	l.demoMu.Unlock()
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		defer close(dp.done)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[demo] serve: %v", err)
		}
	}()
	return nil
}

func (l *Lab) stopDemo() {
	l.demoMu.Lock()
	dp := l.demo
	l.demo = nil
	l.demoMu.Unlock()
	if dp == nil {
		return
	}
	_ = dp.srv.Close()
	_ = dp.ln.Close()
	select {
	case <-dp.done:
	case <-time.After(3 * time.Second):
	}
	l.sessions.CloseAll("demo-stop")
}

func (l *Lab) demoState() (tlsOn bool, addr string, running bool) {
	l.demoMu.RLock()
	defer l.demoMu.RUnlock()
	if l.demo == nil {
		return l.tlsMgr.Enabled(), l.cfg.DemoAddr, false
	}
	return l.demo.tlsOn, l.demo.addr, true
}

func (l *Lab) demoAddr() string {
	l.demoMu.RLock()
	defer l.demoMu.RUnlock()
	if l.demo != nil && l.demo.addr != "" {
		return l.demo.addr
	}
	return l.cfg.DemoAddr
}

func (l *Lab) controlAddr() string {
	if l.controlLn != nil {
		return l.controlLn.Addr().String()
	}
	return l.cfg.ControlAddr
}

func (l *Lab) switchTLS(enabled bool) error {
	l.switchMu.Lock()
	defer l.switchMu.Unlock()

	if strings.HasPrefix(l.tlsMgr.State(), "switching") {
		return errSwitchBusy
	}
	if l.tlsMgr.Enabled() == enabled {
		return nil
	}
	old := l.tlsMgr.Enabled()
	targetState := "switching_off"
	if enabled {
		targetState = "switching_on"
	}
	l.tlsMgr.SetState(targetState)
	l.events.Publish(Event{
		Layer:   "system",
		Type:    "tls.switching",
		Summary: "正在切换 TLS 传输层",
		Data:    map[string]any{"target": enabled},
	})

	l.stopDemo()
	l.tlsMgr.SetEnabled(enabled)
	if err := l.startDemo(enabled); err != nil {
		l.tlsMgr.SetEnabled(old)
		if restartErr := l.startDemo(old); restartErr != nil {
			l.tlsMgr.SetState("error")
			l.events.Publish(Event{Layer: "system", Type: "tls.switch_failed", Summary: "TLS 切换失败且回滚失败", Data: map[string]any{"error": err.Error()}})
			return fmt.Errorf("switch tls: %w (rollback failed: %v)", err, restartErr)
		}
		l.tlsMgr.SetState("error")
		l.events.Publish(Event{Layer: "system", Type: "tls.switch_failed", Summary: "TLS 切换失败，已回滚", Data: map[string]any{"error": err.Error()}})
		return fmt.Errorf("switch tls: %w", err)
	}
	if enabled {
		l.tlsMgr.SetState("on")
	} else {
		l.tlsMgr.SetState("off")
	}
	scheme := "http"
	if enabled {
		scheme = "https"
	}
	l.events.Publish(Event{
		Layer:   "system",
		Type:    "tls.switched",
		Summary: "演示面已切换到 " + scheme,
		Data: map[string]any{
			"enabled": enabled,
			"scheme":  scheme,
			"addr":    l.demoAddr(),
			"cert":    l.tlsMgr.CertInfo(),
		},
	})
	return nil
}

func (l *Lab) Status() map[string]any {
	tlsOn, addr, running := l.demoState()
	scheme := "http"
	if tlsOn {
		scheme = "https"
	}
	return map[string]any{
		"ok":      true,
		"app":     "tcpscope",
		"version": "2.0",
		"mode":    "stack",
		"control": map[string]any{"addr": l.controlAddr(), "scheme": "http"},
		"demo": map[string]any{
			"addr":    addr,
			"scheme":  scheme,
			"running": running,
			"tls": map[string]any{
				"enabled": tlsMgrEnabled(l.tlsMgr),
				"state":   l.tlsMgr.State(),
				"cert":    l.tlsMgr.CertInfo(),
			},
		},
		"sessions":  map[string]any{"active": l.sessions.Count(), "max": l.cfg.MaxSessions},
		"protocols": []string{"tcp", "tls", "http", "ws"},
		"uptime":    time.Since(l.startedAt).Round(time.Second).String(),
	}
}

func tlsMgrEnabled(m *TLSManager) bool { return m.Enabled() }

func (l *Lab) demoMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/demo/hello", l.withHTTPSession(l.handleHello))
	mux.HandleFunc("/demo/echo", l.withHTTPSession(l.handleEcho))
	mux.HandleFunc("/demo/info", l.withHTTPSession(l.handleInfo))
	mux.HandleFunc("/demo/delay", l.withHTTPSession(l.handleDelay))
	mux.HandleFunc("/demo/ws", l.handleDemoWS)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"service": "tcpscope demo plane",
			"routes":  []string{"GET /demo/hello", "POST /demo/echo", "GET /demo/info", "GET /demo/delay?ms=200", "GET /demo/ws"},
			"tls":     r.TLS != nil,
		})
	})
	return withSecurityHeaders(mux)
}

func (l *Lab) controlMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", l.handleStatus)
	mux.HandleFunc("/api/tls", l.handleTLS)
	mux.HandleFunc("/api/sessions", l.handleSessions)
	mux.HandleFunc("/api/sessions/", l.handleSessionItem)
	mux.HandleFunc("/api/demo/http", l.handleDemoHTTP)
	mux.HandleFunc("/api/demo/journey", l.handleJourney)
	mux.HandleFunc("/api/demo/ws/open", l.handleDemoWSOpen)
	mux.HandleFunc("/api/demo/ws/send", l.handleDemoWSSend)
	mux.HandleFunc("/api/demo/ws/close", l.handleDemoWSClose)
	mux.HandleFunc("/api/events", l.handleEvents)
	mux.HandleFunc("/api/ws", l.handleControlWS)
	mux.HandleFunc("/api/cert", l.handleCert)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "unknown api", "code": "not_found"})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(embeddedUI)
	})
	return withSecurityHeaders(mux)
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": msg, "code": code})
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method must be "+method)
		return false
	}
	return true
}

func readJSONLimited(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", err.Error())
		return false
	}
	return true
}

// tlsRecordingListener wraps accepted connections so the raw TLS records can
// be observed before crypto/tls consumes them.
type tlsRecordingListener struct {
	net.Listener
	lab *Lab
}

func (l *tlsRecordingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	rc := &recordingConn{Conn: c, lab: l.lab, side: "server"}
	return tls.Server(rc, l.lab.tlsMgr.ServerConfig()), nil
}

// recordingConn parses TLS record headers from the raw wire bytes.
type recordingConn struct {
	net.Conn
	lab   *Lab
	side  string // server|client
	mu    sync.Mutex
	inBuf []byte
	outBuf []byte
	count int
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.feed("in", p[:n])
	}
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.feed("out", p[:n])
	}
	return n, err
}

func (c *recordingConn) feed(dir string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var buf *[]byte
	if dir == "in" {
		buf = &c.inBuf
	} else {
		buf = &c.outBuf
	}
	*buf = append(*buf, data...)
	for len(*buf) >= 5 && c.count < 300 {
		contentType := (*buf)[0]
		version := binary.BigEndian.Uint16((*buf)[1:3])
		length := int(binary.BigEndian.Uint16((*buf)[3:5]))
		if length > 1<<20 {
			*buf = nil
			return
		}
		if len(*buf) < 5+length {
			break
		}
		payload := (*buf)[5 : 5+length]
		c.count++
		c.lab.publishTLSRecord(c.side, dir, contentType, version, length, payload)
		*buf = (*buf)[5+length:]
	}
	if len(*buf) > 1<<20 {
		*buf = nil
	}
}

func (l *Lab) publishTLSRecord(side, dir string, contentType byte, version uint16, length int, payload []byte) {
	direction := "C2S"
	if (side == "server" && dir == "out") || (side == "client" && dir == "in") {
		direction = "S2C"
	}
	hexPayload := payload
	if len(hexPayload) > 64 {
		hexPayload = hexPayload[:64]
	}
	l.events.Publish(Event{
		Layer:         "tls",
		Type:          "tls.record",
		Direction:     direction,
		Summary:       fmt.Sprintf("%s · %s · %d bytes", tlsContentTypeName(contentType), tlsRecordVersion(version), length),
		Encrypted:     contentType == 23,
		CipherLen:     length,
		CiphertextHex: hex.EncodeToString(hexPayload),
		Data: map[string]any{
			"contentType": tlsContentTypeName(contentType),
			"version":     tlsRecordVersion(version),
			"length":      length,
			"side":        side,
		},
		View: "wire",
	})
}

func tlsContentTypeName(t byte) string {
	switch t {
	case 20:
		return "change_cipher_spec"
	case 21:
		return "alert"
	case 22:
		return "handshake"
	case 23:
		return "application_data"
	default:
		return fmt.Sprintf("type_%d", t)
	}
}

func tlsRecordVersion(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS1.0"
	case 0x0302:
		return "TLS1.1"
	case 0x0303:
		return "TLS1.2"
	case 0x0304:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}

// Janitor closes idle sessions periodically.
func (l *Lab) runJanitor(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.sessions.Janitor(2*time.Minute, 5*time.Minute)
		}
	}
}
