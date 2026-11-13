package main

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"
)

// Event is one observation from any protocol layer. Plaintext is only
// serialized to clients that explicitly ask for reveal=1.
type Event struct {
	Seq           uint64         `json:"seq"`
	TS            string         `json:"ts"`
	SessionID     string         `json:"sessionId,omitempty"`
	Layer         string         `json:"layer"`
	Type          string         `json:"type"`
	Direction     string         `json:"direction,omitempty"`
	Summary       string         `json:"summary"`
	Encrypted     bool           `json:"encrypted,omitempty"`
	CipherLen     int            `json:"cipherLen,omitempty"`
	CiphertextHex string         `json:"ciphertextHex,omitempty"`
	TLSRecordRef  string         `json:"tlsRecordRef,omitempty"`
	Plaintext     map[string]any `json:"plaintext,omitempty"`
	Data          map[string]any `json:"data,omitempty"`
	View          string         `json:"view,omitempty"`
}

// Sanitize strips endpoint plaintext unless the caller asked for it.
func (e Event) Sanitize(reveal bool) Event {
	if !reveal {
		e.Plaintext = nil
	}
	return e
}

// Counters are per-session totals.
type Counters struct {
	Requests  int   `json:"requests"`
	Responses int   `json:"responses"`
	WSIn      int   `json:"wsIn"`
	WSOut     int   `json:"wsOut"`
	BytesIn   int64 `json:"bytesIn"`
	BytesOut  int64 `json:"bytesOut"`
}

// SessionSnapshot is a lock-free copy safe to marshal.
type SessionSnapshot struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Transport  string   `json:"transport"`
	LocalAddr  string   `json:"localAddr"`
	RemoteAddr string   `json:"remoteAddr"`
	State      string   `json:"state"`
	Created    string   `json:"created"`
	LastSeen   string   `json:"lastSeen"`
	Counters   Counters `json:"counters"`
	TLS        *TLSInfo `json:"tls,omitempty"`
}

// Session is one HTTP request or one WebSocket connection. Both the client
// and server side of a lab interaction get a session so the UI can compare
// them.
type Session struct {
	Snapshot  SessionSnapshot
	mu        sync.Mutex
	events    []Event
	frames    []FrameRecord
	closeFn   func(reason string)
	lastAt    time.Time
}

const (
	maxSessionEvents = 500
	maxSessionFrames = 500
)

func (s *Session) Touch() {
	s.mu.Lock()
	s.lastAt = time.Now()
	s.Snapshot.LastSeen = s.lastAt.Format("15:04:05.000")
	s.mu.Unlock()
}

func (s *Session) SetCloseFn(fn func(reason string)) {
	s.mu.Lock()
	s.closeFn = fn
	s.mu.Unlock()
}

func (s *Session) Close(reason string) {
	s.mu.Lock()
	fn := s.closeFn
	s.closeFn = nil
	s.Snapshot.State = "closed"
	s.Snapshot.LastSeen = time.Now().Format("15:04:05.000")
	s.mu.Unlock()
	if fn != nil {
		fn(reason)
	}
}

func (s *Session) AddEvent(ev Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = appendBoundedEvent(s.events, ev, maxSessionEvents)
	s.lastAt = time.Now()
	s.Snapshot.LastSeen = s.lastAt.Format("15:04:05.000")
}

func (s *Session) AddFrame(fr FrameRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frames = appendBoundedFrame(s.frames, fr, maxSessionFrames)
	s.lastAt = time.Now()
	s.Snapshot.LastSeen = s.lastAt.Format("15:04:05.000")
}

func (s *Session) AddCounters(fn func(*Counters)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.Snapshot.Counters)
}

func (s *Session) SetTLS(info *TLSInfo) {
	s.mu.Lock()
	s.Snapshot.TLS = info
	s.mu.Unlock()
}

func (s *Session) SetState(state string) {
	s.mu.Lock()
	s.Snapshot.State = state
	s.mu.Unlock()
}

func (s *Session) SnapshotCopy() SessionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Snapshot
}

type SessionDetail struct {
	SessionSnapshot
	Events []Event       `json:"events"`
	Frames []FrameRecord `json:"frames"`
}

func (s *Session) Detail(reveal bool) SessionDetail {
	s.mu.Lock()
	defer s.mu.Unlock()
	events := make([]Event, len(s.events))
	for i, ev := range s.events {
		events[i] = ev.Sanitize(reveal)
	}
	frames := make([]FrameRecord, len(s.frames))
	copy(frames, s.frames)
	if !reveal && s.Snapshot.Transport == "tls" {
		for i := range frames {
			frames[i].PayloadText = ""
			frames[i].PayloadHex = ""
			frames[i].RawHex = ""
		}
	}
	return SessionDetail{SessionSnapshot: s.Snapshot, Events: events, Frames: frames}
}

func appendBoundedEvent(in []Event, v Event, max int) []Event {
	if len(in) < max {
		return append(in, v)
	}
	copy(in, in[1:])
	in[len(in)-1] = v
	return in
}

func appendBoundedFrame(in []FrameRecord, v FrameRecord, max int) []FrameRecord {
	if len(in) < max {
		return append(in, v)
	}
	copy(in, in[1:])
	in[len(in)-1] = v
	return in
}

// SessionRegistry owns all live sessions and enforces a hard cap.
type SessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	max      int
	next     uint64
}

func NewSessionRegistry(max int) *SessionRegistry {
	if max < 1 {
		max = 1
	}
	return &SessionRegistry{sessions: make(map[string]*Session), max: max}
}

func (r *SessionRegistry) New(kind, transport, local, remote string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.sessions) >= r.max {
		oldestID := ""
		var oldest time.Time
		for id, s := range r.sessions {
			s.mu.Lock()
			at := s.lastAt
			s.mu.Unlock()
			if oldestID == "" || at.Before(oldest) {
				oldestID, oldest = id, at
			}
		}
		if oldestID == "" {
			break
		}
		s := r.sessions[oldestID]
		delete(r.sessions, oldestID)
		go s.Close("evicted")
	}
	r.next++
	now := time.Now()
	s := &Session{
		Snapshot: SessionSnapshot{
			ID:         fmt.Sprintf("s-%d", r.next),
			Kind:       kind,
			Transport:  transport,
			LocalAddr:  local,
			RemoteAddr: remote,
			State:      "open",
			Created:    now.Format("15:04:05.000"),
			LastSeen:   now.Format("15:04:05.000"),
		},
		lastAt: now,
	}
	r.sessions[s.Snapshot.ID] = s
	return s
}

func (r *SessionRegistry) Get(id string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[id]
	return s, ok
}

func (r *SessionRegistry) List() []SessionSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]SessionSnapshot, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s.SnapshotCopy())
	}
	return out
}

func (r *SessionRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

func (r *SessionRegistry) Close(id, reason string) bool {
	r.mu.Lock()
	s, ok := r.sessions[id]
	if ok {
		delete(r.sessions, id)
	}
	r.mu.Unlock()
	if ok {
		s.Close(reason)
	}
	return ok
}

func (r *SessionRegistry) CloseAll(reason string) {
	r.mu.Lock()
	list := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		list = append(list, s)
	}
	r.sessions = make(map[string]*Session)
	r.mu.Unlock()
	for _, s := range list {
		s.Close(reason)
	}
}

// Janitor closes sessions that have been idle for too long.
func (r *SessionRegistry) Janitor(idleHTTP, idleWS time.Duration) {
	now := time.Now()
	r.mu.RLock()
	var stale []*Session
	for _, s := range r.sessions {
		s.mu.Lock()
		idle := now.Sub(s.lastAt)
		kind := s.Snapshot.Kind
		s.mu.Unlock()
		limit := idleHTTP
		if kind == "ws" {
			limit = idleWS
		}
		if idle > limit {
			stale = append(stale, s)
		}
	}
	r.mu.RUnlock()
	for _, s := range stale {
		r.Close(s.Snapshot.ID, "idle-timeout")
	}
}

// EventBus is a bounded, fan-out event log.
type EventBus struct {
	mu     sync.RWMutex
	seq    uint64
	ring   []Event
	max    int
	subs   map[uint64]chan Event
	nextID uint64
	closed bool
}

func NewEventBus(max int) *EventBus {
	if max < 1 {
		max = 1
	}
	return &EventBus{max: max, subs: make(map[uint64]chan Event)}
}

func (b *EventBus) Publish(ev Event) Event {
	b.mu.Lock()
	b.seq++
	ev.Seq = b.seq
	if ev.TS == "" {
		ev.TS = time.Now().Format("15:04:05.000")
	}
	b.ring = appendBoundedEvent(b.ring, ev, b.max)
	subs := make([]chan Event, 0, len(b.subs))
	for _, ch := range b.subs {
		subs = append(subs, ch)
	}
	b.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
			// Slow subscriber: drop this event rather than blocking the
			// protocol path. The UI can refetch with Since on reconnect.
		}
	}
	return ev
}

func (b *EventBus) LatestSeq() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.seq
}

func (b *EventBus) Since(seq uint64, limit int) []Event {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Event, 0, len(b.ring))
	for _, ev := range b.ring {
		if ev.Seq > seq {
			out = append(out, ev)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func (b *EventBus) Subscribe() (uint64, <-chan Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextID++
	id := b.nextID
	ch := make(chan Event, 256)
	b.subs[id] = ch
	cancel := func() {
		b.mu.Lock()
		if c, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(c)
		}
		b.mu.Unlock()
	}
	return id, ch, cancel
}

func (b *EventBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for id, ch := range b.subs {
		delete(b.subs, id)
		close(ch)
	}
}

// FrameRecord is a TCP frame reconstructed from real application bytes.
type FrameRecord struct {
	ID            uint64   `json:"id"`
	SessionID     string   `json:"sessionId"`
	Timestamp     string   `json:"timestamp"`
	Direction     string   `json:"direction"`
	SrcPort       uint16   `json:"srcPort"`
	DstPort       uint16   `json:"dstPort"`
	Flags         TCPFlags `json:"flags"`
	RelSeq        uint32   `json:"relSeq"`
	RelAck        uint32   `json:"relAck"`
	RawSeq        uint32   `json:"rawSeq"`
	RawAck        uint32   `json:"rawAck"`
	WindowSize    uint16   `json:"windowSize"`
	Checksum      string   `json:"checksum"`
	PayloadLen    int      `json:"payloadLen"`
	PayloadHex    string   `json:"payloadHex"`
	PayloadText   string   `json:"payloadText"`
	RawHex        string   `json:"rawHex"`
	Binary        bool     `json:"binary"`
	Layer         string   `json:"layer"`
	Note          string   `json:"note"`
	Reconstructed bool     `json:"reconstructed"`
}

var frameSeq uint64
var frameMu sync.Mutex

func buildFrame(sessionID, direction string, srcPort, dstPort uint16, seq, ack uint32, flags TCPFlags, payload []byte, layer, note string) FrameRecord {
	raw, csum := BuildRawTCPHeaderAndChecksum(srcPort, dstPort, seq, ack, flags, 65535, payload)
	frameMu.Lock()
	frameSeq++
	id := frameSeq
	frameMu.Unlock()
	text := ""
	binary := false
	if utf8.Valid(payload) && isMostlyPrintable(payload) {
		text = string(payload)
	} else if len(payload) > 0 {
		binary = true
	}
	return FrameRecord{
		ID:            id,
		SessionID:     sessionID,
		Timestamp:     time.Now().Format("15:04:05.000"),
		Direction:     direction,
		SrcPort:       srcPort,
		DstPort:       dstPort,
		Flags:         flags,
		RelSeq:        seq,
		RelAck:        ack,
		RawSeq:        seq,
		RawAck:        ack,
		WindowSize:    65535,
		Checksum:      fmt.Sprintf("0x%04X", csum),
		PayloadLen:    len(payload),
		PayloadHex:    hex.EncodeToString(payload),
		PayloadText:   text,
		RawHex:        hex.EncodeToString(raw),
		Binary:        binary,
		Layer:         layer,
		Note:          note,
		Reconstructed: true,
	}
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	printable := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 32 && c <= 126) {
			printable++
		}
	}
	return printable*10 >= len(b)*9
}
