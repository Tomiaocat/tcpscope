package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
)

func (l *Lab) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, l.Status())
}

func (l *Lab) handleTLS(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if !readJSONLimited(w, r, &req, 1<<14) {
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "missing_enabled", "enabled is required")
		return
	}
	if err := l.switchTLS(*req.Enabled); err != nil {
		if errors.Is(err, errSwitchBusy) {
			writeError(w, http.StatusConflict, "switch_busy", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "switch_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, l.Status())
}

func (l *Lab) handleSessions(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	list := l.sessions.List()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"sessions": list,
		"count":    len(list),
		"latest":   l.events.LatestSeq(),
	})
}

func (l *Lab) handleSessionItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, "bad_session", "session id is required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		sess, ok := l.sessions.Get(id)
		if !ok {
			writeError(w, http.StatusNotFound, "session_not_found", "no such session")
			return
		}
		reveal := r.URL.Query().Get("reveal") == "1"
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "session": sess.Detail(reveal)})
	case http.MethodDelete:
		if !l.sessions.Close(id, "api-close") {
			writeError(w, http.StatusNotFound, "session_not_found", "no such session")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		w.Header().Set("Allow", "GET, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or DELETE")
	}
}

func (l *Lab) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	reveal := r.URL.Query().Get("reveal") == "1"
	events := l.events.Since(since, limit)
	out := make([]Event, len(events))
	for i, ev := range events {
		out[i] = ev.Sanitize(reveal)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"latest": l.events.LatestSeq(),
		"events": out,
		"reveal": reveal,
	})
}

func (l *Lab) handleCert(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	pemBytes := l.tlsMgr.CertPEM()
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=tcpscope-cert.pem")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(pemBytes)
}

func (l *Lab) handleControlWS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method must be GET", http.StatusMethodNotAllowed)
		return
	}
	ws, err := Upgrade(w, r, defaultWSOptions())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	reveal := r.URL.Query().Get("reveal") == "1"
	since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	l.controlWSMu.Lock()
	l.controlWS[ws] = struct{}{}
	l.controlWSMu.Unlock()
	var peerClosed atomic.Bool
	defer func() {
		l.controlWSMu.Lock()
		delete(l.controlWS, ws)
		l.controlWSMu.Unlock()
		if peerClosed.Load() {
			_ = ws.conn.Close()
		} else {
			_ = ws.Close()
		}
	}()

	for _, ev := range l.events.Since(since, 1000) {
		if err := sendWSEvent(ws, ev.Sanitize(reveal)); err != nil {
			return
		}
	}
	_, ch, cancel := l.events.Subscribe()
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := ws.ReadMessage(); err != nil {
				peerClosed.Store(true)
				_ = ws.conn.Close()
				return
			}
		}
	}()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-done:
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if err := sendWSEvent(ws, ev.Sanitize(reveal)); err != nil {
				return
			}
		}
	}
}

func sendWSEvent(ws *WSConn, ev Event) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return ws.WriteMessage(wsOpText, data)
}

func (l *Lab) closeControlWS() {
	l.controlWSMu.Lock()
	list := make([]*WSConn, 0, len(l.controlWS))
	for ws := range l.controlWS {
		list = append(list, ws)
	}
	l.controlWS = make(map[*WSConn]struct{})
	l.controlWSMu.Unlock()
	for _, ws := range list {
		_ = ws.Close()
	}
}
