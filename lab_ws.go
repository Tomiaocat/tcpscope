package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

type labWSClient struct {
	SessionID string
	Conn      *WSConn
}

type wsOpenReq struct {
	Path   string `json:"path"`
	Reveal bool   `json:"reveal"`
}

type wsSendReq struct {
	SessionID string `json:"sessionId"`
	Type      string `json:"type"`
	Data      string `json:"data"`
}

type wsCloseReq struct {
	SessionID string `json:"sessionId"`
	Code      int    `json:"code"`
	Reason    string `json:"reason"`
}

func (l *Lab) handleDemoWS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method must be GET", http.StatusMethodNotAllowed)
		return
	}
	ws, err := Upgrade(w, r, defaultWSOptions())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	transport := "plain"
	if r.TLS != nil {
		transport = "tls"
	}
	sess := l.sessions.New("ws", transport, localAddrString(r), r.RemoteAddr)
	if r.TLS != nil {
		info := l.tlsMgr.InfoFromState(*r.TLS, true)
		sess.SetTLS(info)
		l.publishHandshake(sess.Snapshot.ID, "server", info)
	}
	sess.SetCloseFn(func(reason string) {
		_ = ws.WriteClose(1001, reason)
		_ = ws.conn.Close()
	})
	l.publishWS("ws.open", sess, "S2C", "WebSocket 已建立", transport, "server", map[string]any{
		"transport": transport,
		"remote":    r.RemoteAddr,
	})
	_ = ws.WriteMessage(wsOpText, []byte("welcome to tcpscope ws · echo the same message back"))

	for {
		op, payload, err := ws.ReadMessage()
		if err != nil {
			break
		}
		l.publishWSFrame(sess, "C2S", op, payload, transport, "server")
		if err := ws.WriteMessage(op, payload); err != nil {
			break
		}
		l.publishWSFrame(sess, "S2C", op, payload, transport, "server")
	}
	l.publishWS("ws.close", sess, "S2C", "WebSocket 已关闭", transport, "server", nil)
	sess.SetState("closed")
	l.sessions.Close(sess.Snapshot.ID, "ws-closed")
}

func (l *Lab) handleDemoWSOpen(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req wsOpenReq
	if !readJSONLimited(w, r, &req, 1<<16) {
		return
	}
	if req.Path == "" {
		req.Path = "/demo/ws"
	}
	if !strings.HasPrefix(req.Path, "/demo/ws") {
		writeError(w, http.StatusBadRequest, "bad_path", "path must be /demo/ws")
		return
	}
	scheme := "ws"
	transport := "plain"
	if l.tlsMgr.Enabled() {
		scheme = "wss"
		transport = "tls"
	}
	rawURL := scheme + "://" + l.demoAddr() + req.Path
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	ws, err := Dial(ctx, rawURL, l.tlsMgr.ClientConfig(), defaultWSOptions())
	if err != nil {
		writeError(w, http.StatusBadGateway, "ws_dial_failed", err.Error())
		return
	}
	sess := l.sessions.New("ws", transport, "client", rawURL)
	var tlsInfo *TLSInfo
	if ws.TLSState() != nil {
		tlsInfo = l.tlsMgr.InfoFromState(*ws.TLSState(), false)
		sess.SetTLS(tlsInfo)
		l.publishHandshake(sess.Snapshot.ID, "client", tlsInfo)
	}
	client := &labWSClient{SessionID: sess.Snapshot.ID, Conn: ws}
	l.wsMu.Lock()
	l.wsClients[sess.Snapshot.ID] = client
	l.wsMu.Unlock()
	sess.SetCloseFn(func(reason string) {
		_ = ws.WriteClose(1001, reason)
		_ = ws.conn.Close()
		l.wsMu.Lock()
		delete(l.wsClients, sess.Snapshot.ID)
		l.wsMu.Unlock()
	})
	l.publishWS("ws.open", sess, "S2C", "客户端 WebSocket 已连接", transport, "client", map[string]any{
		"url": rawURL,
	})
	go l.readWSClient(client, sess, transport)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"sessionId": sess.Snapshot.ID,
		"url":       rawURL,
		"transport": transport,
		"tls":       tlsInfo,
	})
}

func (l *Lab) readWSClient(client *labWSClient, sess *Session, transport string) {
	for {
		op, payload, err := client.Conn.ReadMessage()
		if err != nil {
			break
		}
		l.publishWSFrame(sess, "S2C", op, payload, transport, "client")
	}
	l.publishWS("ws.close", sess, "S2C", "客户端 WebSocket 已关闭", transport, "client", nil)
	sess.SetState("closed")
	l.sessions.Close(sess.Snapshot.ID, "ws-closed")
}

func (l *Lab) handleDemoWSSend(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req wsSendReq
	if !readJSONLimited(w, r, &req, 1<<20) {
		return
	}
	client, sess, ok := l.findWSClient(req.SessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "ws_not_found", "no such websocket session")
		return
	}
	op := byte(wsOpText)
	if req.Type == "binary" {
		op = wsOpBinary
	}
	payload := []byte(req.Data)
	if req.Type == "binary" {
		decoded, err := hex.DecodeString(req.Data)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_hex", err.Error())
			return
		}
		payload = decoded
	}
	if err := client.Conn.WriteMessage(op, payload); err != nil {
		writeError(w, http.StatusBadGateway, "ws_write_failed", err.Error())
		return
	}
	transport := sess.Snapshot.Transport
	l.publishWSFrame(sess, "C2S", op, payload, transport, "client")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sessionId": req.SessionID, "bytes": len(payload)})
}

func (l *Lab) handleDemoWSClose(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req wsCloseReq
	if !readJSONLimited(w, r, &req, 1<<16) {
		return
	}
	client, sess, ok := l.findWSClient(req.SessionID)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "alreadyClosed": true})
		return
	}
	code := req.Code
	if code == 0 {
		code = 1000
	}
	sess.SetCloseFn(nil)
	_ = client.Conn.WriteClose(code, req.Reason)
	_ = client.Conn.conn.Close()
	l.wsMu.Lock()
	delete(l.wsClients, req.SessionID)
	l.wsMu.Unlock()
	l.publishWS("ws.close", sess, "C2S", "客户端主动关闭 WebSocket", sess.Snapshot.Transport, "client", map[string]any{"code": code})
	sess.SetState("closed")
	l.sessions.Close(sess.Snapshot.ID, "ws-closed")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (l *Lab) findWSClient(id string) (*labWSClient, *Session, bool) {
	if id == "" {
		return nil, nil, false
	}
	l.wsMu.Lock()
	client, ok := l.wsClients[id]
	l.wsMu.Unlock()
	if !ok {
		return nil, nil, false
	}
	sess, ok := l.sessions.Get(id)
	if !ok {
		return nil, nil, false
	}
	return client, sess, true
}

func (l *Lab) closeAllWSClient() {
	l.wsMu.Lock()
	clients := make([]*labWSClient, 0, len(l.wsClients))
	for _, c := range l.wsClients {
		clients = append(clients, c)
	}
	l.wsClients = make(map[string]*labWSClient)
	l.wsMu.Unlock()
	for _, c := range clients {
		_ = c.Conn.Close()
	}
}

func (l *Lab) publishWSFrame(sess *Session, dir string, opcode byte, payload []byte, transport, side string) {
	kind := "text"
	if opcode == wsOpBinary {
		kind = "binary"
	}
	plain := map[string]any{
		"opcode": kind,
		"size":   len(payload),
		"side":   side,
	}
	if opcode == wsOpText && utf8.Valid(payload) {
		plain["data"] = string(payload)
	} else {
		plain["hex"] = hex.EncodeToString(payload)
	}
	ev := Event{
		Layer:     "ws",
		Type:      "ws.frame",
		SessionID: sess.Snapshot.ID,
		Direction: dir,
		Summary:   fmt.Sprintf("%s · %s · %d B", dir, kind, len(payload)),
		Encrypted: transport == "tls",
		CipherLen: len(payload),
		Plaintext: plain,
		Data:      map[string]any{"side": side, "opcode": kind},
		View:      "endpoint",
	}
	l.events.Publish(ev)
	sess.AddEvent(ev)
	sess.AddCounters(func(c *Counters) {
		if dir == "C2S" {
			c.WSIn++
			c.BytesIn += int64(len(payload))
		} else {
			c.WSOut++
			c.BytesOut += int64(len(payload))
		}
	})
	cPort, _ := portOf(sess.Snapshot.RemoteAddr)
	sPort, _ := portOf(sess.Snapshot.LocalAddr)
	if side == "client" {
		cPort, sPort = 52000, mustPort(l.demoAddr())
	}
	frame := buildFrame(sess.Snapshot.ID, dir, cPort, sPort, 1, 1, TCPFlags{PSH: true, ACK: true}, payload, "ws", "WS 帧")
	sess.AddFrame(frame)
	l.publishFrame(frame)
}

func (l *Lab) publishWS(typ string, sess *Session, dir, summary, transport, side string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["side"] = side
	ev := Event{
		Layer:     "ws",
		Type:      typ,
		SessionID: sess.Snapshot.ID,
		Direction: dir,
		Summary:   summary,
		Encrypted: transport == "tls",
		Data:      data,
		View:      "endpoint",
	}
	l.events.Publish(ev)
	sess.AddEvent(ev)
}

func mustPort(addr string) uint16 {
	p, _ := portOf(addr)
	return p
}
