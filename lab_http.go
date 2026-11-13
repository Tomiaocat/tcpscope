package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type demoHTTPReq struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Reveal  bool              `json:"reveal"`
}

type captureWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (c *captureWriter) WriteHeader(status int) {
	c.status = status
	c.ResponseWriter.WriteHeader(status)
}

func (c *captureWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	c.body.Write(p)
	return c.ResponseWriter.Write(p)
}

func (c *captureWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (l *Lab) withHTTPSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		transport := "plain"
		if r.TLS != nil {
			transport = "tls"
		}
		sess := l.sessions.New("http", transport, localAddrString(r), r.RemoteAddr)
		if r.TLS != nil {
			info := l.tlsMgr.InfoFromState(*r.TLS, true)
			sess.SetTLS(info)
			l.publishHandshake(sess.Snapshot.ID, "server", info)
		}
		reqDump, _ := httputil.DumpRequest(r, true)
		reqEvent := Event{
			Layer:     "http",
			Type:      "http.request",
			SessionID: sess.Snapshot.ID,
			Direction: "C2S",
			Summary:   fmt.Sprintf("%s %s · %d B", r.Method, r.URL.RequestURI(), len(reqDump)),
			Encrypted: transport == "tls",
			CipherLen: len(reqDump),
			Plaintext: map[string]any{
				"method":  r.Method,
				"path":    r.URL.RequestURI(),
				"headers": safeHeaders(r.Header),
				"body":    string(reqDump),
				"size":    len(reqDump),
			},
			View: "endpoint",
		}
		l.events.Publish(reqEvent)
		sess.AddEvent(reqEvent)
		sess.AddCounters(func(c *Counters) { c.Requests++; c.BytesIn += int64(len(reqDump)) })

		rec := &captureWriter{ResponseWriter: w, status: http.StatusOK}
		next(rec, r)
		respBytes := dumpCaptured(rec)
		respEvent := Event{
			Layer:     "http",
			Type:      "http.response",
			SessionID: sess.Snapshot.ID,
			Direction: "S2C",
			Summary:   fmt.Sprintf("%d %s · %d B", rec.status, http.StatusText(rec.status), len(respBytes)),
			Encrypted: transport == "tls",
			CipherLen: len(respBytes),
			Plaintext: map[string]any{
				"status":  rec.status,
				"headers": safeHeaders(rec.Header()),
				"body":    rec.body.String(),
				"size":    len(respBytes),
			},
			View: "endpoint",
		}
		l.events.Publish(respEvent)
		sess.AddEvent(respEvent)
		sess.AddCounters(func(c *Counters) { c.Responses++; c.BytesOut += int64(len(respBytes)) })
		sess.SetState("done")

		// Reconstruct the two TCP segments from the real byte streams.
		cPort, _ := portOf(r.RemoteAddr)
		sPort, _ := portOf(localAddrString(r))
		c2s := buildFrame(sess.Snapshot.ID, "C2S", cPort, sPort, 1, 1, TCPFlags{PSH: true, ACK: true}, reqDump, "http", "HTTP 请求")
		s2c := buildFrame(sess.Snapshot.ID, "S2C", sPort, cPort, 1, uint32(len(reqDump))+1, TCPFlags{PSH: true, ACK: true}, respBytes, "http", "HTTP 响应")
		sess.AddFrame(c2s)
		sess.AddFrame(s2c)
		l.publishFrame(c2s)
		l.publishFrame(s2c)
	}
}

func (l *Lab) publishHandshake(sessionID, side string, info *TLSInfo) {
	if info == nil {
		return
	}
	ev := Event{
		Layer:     "tls",
		Type:      "tls.handshake",
		SessionID: sessionID,
		Direction: side,
		Summary:   fmt.Sprintf("%s · %s · %s", info.Version, info.Cipher, info.ALPN),
		Data: map[string]any{
			"version":   info.Version,
			"cipher":    info.Cipher,
			"alpn":      info.ALPN,
			"verified":  info.Verified,
			"serverName": info.ServerName,
			"cert":      info.Cert,
			"side":      side,
		},
		View: "wire",
	}
	l.events.Publish(ev)
	if s, ok := l.sessions.Get(sessionID); ok {
		s.AddEvent(ev)
	}
}

func (l *Lab) publishFrame(fr FrameRecord) {
	ev := Event{
		Layer:     "tcp",
		Type:      "tcp.frame",
		SessionID: fr.SessionID,
		Direction: fr.Direction,
		Summary:   fmt.Sprintf("%s · %s · %d B", fr.Direction, flagsString(fr.Flags), fr.PayloadLen),
		Data: map[string]any{
			"srcPort": fr.SrcPort,
			"dstPort": fr.DstPort,
			"flags":   fr.Flags,
			"seq":     fr.RawSeq,
			"ack":     fr.RawAck,
			"len":     fr.PayloadLen,
			"layer":   fr.Layer,
			"note":    fr.Note,
		},
		Plaintext: map[string]any{
			"payloadHex":  fr.PayloadHex,
			"payloadText": fr.PayloadText,
			"rawHex":      fr.RawHex,
		},
		View: "endpoint",
	}
	l.events.Publish(ev)
	if s, ok := l.sessions.Get(fr.SessionID); ok {
		s.AddEvent(ev)
	}
}

func flagsString(f TCPFlags) string {
	var out []string
	if f.SYN {
		out = append(out, "SYN")
	}
	if f.ACK {
		out = append(out, "ACK")
	}
	if f.PSH {
		out = append(out, "PSH")
	}
	if f.FIN {
		out = append(out, "FIN")
	}
	if f.RST {
		out = append(out, "RST")
	}
	if f.URG {
		out = append(out, "URG")
	}
	return "[" + strings.Join(out, ", ") + "]"
}

func dumpCaptured(rec *captureWriter) []byte {
	var b strings.Builder
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	b.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", status, http.StatusText(status)))
	_ = rec.Header().Write(&b)
	b.WriteString("\r\n")
	b.Write(rec.body.Bytes())
	return []byte(b.String())
}

func safeHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Cookie") {
			out[k] = "[redacted]"
			continue
		}
		out[k] = strings.Join(v, ", ")
	}
	return out
}

func localAddrString(r *http.Request) string {
	if v := r.Context().Value(http.LocalAddrContextKey); v != nil {
		if a, ok := v.(net.Addr); ok {
			return a.String()
		}
	}
	return r.Host
}

func portOf(addr string) (uint16, error) {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return 0, err
	}
	return uint16(n), nil
}

func transportOf(r *http.Request) string {
	if r.TLS != nil {
		return "tls"
	}
	return "plain"
}

func (l *Lab) handleHello(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	n := l.helloCount.Add(1)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"message":      "hello",
		"serverTime":   time.Now().Format(time.RFC3339Nano),
		"requestCount": n,
		"transport":    transportOf(r),
	})
}

func (l *Lab) handleEcho(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", err.Error())
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (l *Lab) handleInfo(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	var tlsInfo *TLSInfo
	if r.TLS != nil {
		tlsInfo = l.tlsMgr.InfoFromState(*r.TLS, true)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"method":    r.Method,
		"path":      r.URL.RequestURI(),
		"proto":     r.Proto,
		"remote":    r.RemoteAddr,
		"local":     localAddrString(r),
		"headers":   safeHeaders(r.Header),
		"transport": transportOf(r),
		"tls":       tlsInfo,
	})
}

func (l *Lab) handleDelay(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	ms, _ := strconv.Atoi(r.URL.Query().Get("ms"))
	if ms < 0 {
		ms = 0
	}
	if ms > 5000 {
		ms = 5000
	}
	time.Sleep(time.Duration(ms) * time.Millisecond)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "delayedMs": ms, "transport": transportOf(r)})
}

func (l *Lab) demoBaseURL() string {
	scheme := "http"
	if l.tlsMgr.Enabled() {
		scheme = "https"
	}
	return scheme + "://" + l.demoAddr()
}

func (l *Lab) newLabTransport() *http.Transport {
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig:       l.tlsMgr.ClientConfig(),
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		rc := &recordingConn{Conn: raw, lab: l, side: "client"}
		tc := tlsClientHandshake(rc, l.tlsMgr.ClientConfig(), ctx)
		if tc == nil {
			raw.Close()
			return nil, fmt.Errorf("tls handshake failed")
		}
		return tc, nil
	}
	return tr
}

func (l *Lab) handleDemoHTTP(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req demoHTTPReq
	if !readJSONLimited(w, r, &req, 1<<20) {
		return
	}
	if req.Method == "" {
		req.Method = http.MethodGet
	}
	if req.Path == "" {
		req.Path = "/demo/hello"
	}
	if !strings.HasPrefix(req.Path, "/demo/") {
		writeError(w, http.StatusBadRequest, "bad_path", "path must start with /demo/")
		return
	}
	u, err := url.Parse(l.demoBaseURL() + req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_path", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}
	hreq, err := http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), u.String(), bodyReader)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	for k, v := range req.Headers {
		hreq.Header.Set(k, v)
	}
	if req.Body != "" && hreq.Header.Get("Content-Type") == "" {
		hreq.Header.Set("Content-Type", "text/plain; charset=utf-8")
	}
	reqDump, _ := httputil.DumpRequestOut(hreq, true)

	transport := "plain"
	if l.tlsMgr.Enabled() {
		transport = "tls"
	}
	sess := l.sessions.New("http", transport, "client", u.String())
	client := &http.Client{Transport: l.newLabTransport(), Timeout: 20 * time.Second}
	start := time.Now()
	resp, err := client.Do(hreq)
	duration := time.Since(start)
	if err != nil {
		l.events.Publish(Event{Layer: "http", Type: "http.error", SessionID: sess.Snapshot.ID, Summary: err.Error(), View: "endpoint"})
		sess.Close("error")
		writeError(w, http.StatusBadGateway, "request_failed", err.Error())
		return
	}
	defer resp.Body.Close()
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if readErr != nil {
		respBody = append(respBody, []byte("\n[truncated]")...)
	}
	respDump := dumpResponse(resp, respBody)
	var tlsInfo *TLSInfo
	if resp.TLS != nil {
		tlsInfo = l.tlsMgr.InfoFromState(*resp.TLS, false)
		sess.SetTLS(tlsInfo)
		l.publishHandshake(sess.Snapshot.ID, "client", tlsInfo)
	}
	reqPlain := map[string]any{
		"method":  hreq.Method,
		"url":     u.String(),
		"headers": safeHeaders(hreq.Header),
		"body":    req.Body,
		"size":    len(reqDump),
	}
	respPlain := map[string]any{
		"status":  resp.StatusCode,
		"headers": safeHeaders(resp.Header),
		"body":    string(respBody),
		"size":    len(respDump),
	}
	reqEvent := Event{
		Layer: "http", Type: "http.request", SessionID: sess.Snapshot.ID, Direction: "C2S",
		Summary: fmt.Sprintf("%s %s · %d B", hreq.Method, hreq.URL.RequestURI(), len(reqDump)),
		Encrypted: transport == "tls", CipherLen: len(reqDump), Plaintext: reqPlain, View: "endpoint",
	}
	respEvent := Event{
		Layer: "http", Type: "http.response", SessionID: sess.Snapshot.ID, Direction: "S2C",
		Summary: fmt.Sprintf("%d %s · %d B", resp.StatusCode, http.StatusText(resp.StatusCode), len(respDump)),
		Encrypted: transport == "tls", CipherLen: len(respDump), Plaintext: respPlain, View: "endpoint",
	}
	l.events.Publish(reqEvent)
	l.events.Publish(respEvent)
	sess.AddEvent(reqEvent)
	sess.AddEvent(respEvent)
	sess.AddCounters(func(c *Counters) {
		c.Requests++
		c.Responses++
		c.BytesOut += int64(len(reqDump))
		c.BytesIn += int64(len(respDump))
	})
	sess.SetState("done")

	sPort, _ := portOf(l.demoAddr())
	c2s := buildFrame(sess.Snapshot.ID, "C2S", 52000, sPort, 1, 1, TCPFlags{PSH: true, ACK: true}, reqDump, "http", "HTTP 请求")
	s2c := buildFrame(sess.Snapshot.ID, "S2C", sPort, 52000, 1, uint32(len(reqDump))+1, TCPFlags{PSH: true, ACK: true}, respDump, "http", "HTTP 响应")
	sess.AddFrame(c2s)
	sess.AddFrame(s2c)
	l.publishFrame(c2s)
	l.publishFrame(s2c)

	out := map[string]any{
		"ok":         true,
		"sessionId":  sess.Snapshot.ID,
		"transport":  transport,
		"tls":        tlsInfo,
		"durationMs": duration.Milliseconds(),
		"reveal":     req.Reveal,
		"encrypted":  transport == "tls",
	}
	if req.Reveal || transport == "plain" {
		out["request"] = reqPlain
		out["response"] = respPlain
	} else {
		out["request"] = map[string]any{"size": len(reqDump)}
		out["response"] = map[string]any{"size": len(respDump)}
		out["masked"] = true
	}
	writeJSON(w, http.StatusOK, out)
}

func dumpResponse(resp *http.Response, body []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	_ = resp.Header.Write(&b)
	b.WriteString("\r\n")
	b.Write(body)
	return []byte(b.String())
}

func tlsClientHandshake(conn net.Conn, cfg *tls.Config, ctx context.Context) net.Conn {
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil
	}
	return tc
}
