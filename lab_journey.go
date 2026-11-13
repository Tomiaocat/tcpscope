package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

func (l *Lab) handleJourney(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	tlsOn, addr, _ := l.demoState()
	steps := make(map[string]string)
	trace := make(map[string]string)
	var handshake *TLSInfo
	endpoint, err := l.runJourney(ctx, tlsOn, addr, steps, trace, &handshake)
	result := map[string]any{"ok": true, "steps": steps, "endpoint": endpoint}
	result["handshake"] = handshake
	if !tlsOn || r.URL.Query().Get("reveal") == "1" {
		result["trace"] = trace
	}
	if err != nil {
		result["failure"] = err.Error()
	}
	writeJSON(w, http.StatusOK, result)
}

func (l *Lab) runJourney(ctx context.Context, tlsOn bool, addr string, steps, trace map[string]string, handshake **TLSInfo) (string, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("TCP: %w", err)
	}
	defer raw.Close()
	deadline, _ := ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		return "", err
	}
	endpoint := raw.LocalAddr().String() + " → " + raw.RemoteAddr().String()
	steps["tcp"] = "TCP 已连接"
	var conn net.Conn = raw
	var state *tls.ConnectionState
	steps["tls"] = "未启用 · 使用明文"
	if tlsOn {
		delete(steps, "tls")
		secure := tls.Client(raw, l.tlsMgr.ClientConfig())
		if err := secure.HandshakeContext(ctx); err != nil {
			return endpoint, fmt.Errorf("TLS: %w", err)
		}
		s := secure.ConnectionState()
		state = &s
		conn = secure
		info := l.tlsMgr.InfoFromState(s, false)
		*handshake = info
		steps["tls"] = info.Version + " · " + info.Cipher
	}
	reader := bufio.NewReader(conn)
	request := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/demo/hello"}, Host: addr}
	var sent bytes.Buffer
	if err := request.Write(io.MultiWriter(conn, &sent)); err != nil {
		return endpoint, fmt.Errorf("HTTP 请求: %w", err)
	}
	trace["httpRequest"] = sent.String()
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return endpoint, fmt.Errorf("HTTP 响应: %w", err)
	}
	responseDump, err := httputil.DumpResponse(response, true)
	if err != nil {
		return endpoint, fmt.Errorf("HTTP 响应体: %w", err)
	}
	trace["httpResponse"] = string(responseDump)
	response.Body.Close()
	steps["http"] = "GET /demo/hello → " + response.Status
	if response.StatusCode != http.StatusOK || response.Close {
		return endpoint, fmt.Errorf("HTTP 连接无法继续升级")
	}
	ws, err := upgradeClient(conn, reader, &url.URL{Path: "/demo/ws"}, addr, defaultWSOptions(), state, trace)
	if err != nil {
		return endpoint, fmt.Errorf("WebSocket 升级: %w", err)
	}
	defer ws.Close()
	steps["upgrade"] = "GET /demo/ws · Upgrade: websocket → 101 Switching Protocols"
	if _, welcome, err := ws.ReadMessage(); err != nil {
		return endpoint, fmt.Errorf("WebSocket 欢迎帧: %w", err)
	} else {
		trace["welcome"] = string(welcome)
	}
	const message = "hello websocket"
	if err := ws.WriteMessage(wsOpText, []byte(message)); err != nil {
		return endpoint, fmt.Errorf("WebSocket 发送: %w", err)
	}
	trace["wsRequest"] = message
	op, payload, err := ws.ReadMessage()
	if err != nil {
		return endpoint, fmt.Errorf("WebSocket 回显: %w", err)
	}
	if op != wsOpText || string(payload) != message {
		return endpoint, fmt.Errorf("WebSocket 回显内容不匹配")
	}
	steps["ws"] = "文本帧 → 回显「" + string(payload) + "」"
	trace["wsResponse"] = string(payload)
	return endpoint, nil
}
