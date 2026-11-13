package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

// WSOptions controls limits and handshake policy.
type WSOptions struct {
	MaxMessageBytes int64
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	OriginCheck     func(*http.Request) bool
}

func defaultWSOptions() WSOptions {
	return WSOptions{
		MaxMessageBytes: 1 << 20,
		ReadTimeout:     60 * time.Second,
		WriteTimeout:    10 * time.Second,
		OriginCheck:     defaultOriginCheck,
	}
}

func normalizeWSOptions(opts WSOptions) WSOptions {
	def := defaultWSOptions()
	if opts.MaxMessageBytes <= 0 {
		opts.MaxMessageBytes = def.MaxMessageBytes
	}
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = def.ReadTimeout
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = def.WriteTimeout
	}
	if opts.OriginCheck == nil {
		opts.OriginCheck = def.OriginCheck
	}
	return opts
}

// WSConn is a minimal RFC 6455 connection.
type WSConn struct {
	conn     net.Conn
	br       *bufio.Reader
	bw       *bufio.Writer
	role     string // "server" or "client"
	opts     WSOptions
	tlsState *tls.ConnectionState
	wmu      sync.Mutex
	once     sync.Once
}

func (c *WSConn) TLSState() *tls.ConnectionState { return c.tlsState }

type WSCloseError struct {
	Code   int
	Reason string
}

func (e *WSCloseError) Error() string {
	return fmt.Sprintf("websocket closed: %d %s", e.Code, e.Reason)
}

func computeAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, value := range h.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func defaultOriginCheck(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // non-browser client (wscat/curl) is allowed
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	port := u.Port()
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return false
	}
	return port == "19527" || port == ""
}

// Upgrade hijacks an HTTP/1.1 connection and returns a server-side WSConn.
func Upgrade(w http.ResponseWriter, r *http.Request, opts WSOptions) (*WSConn, error) {
	opts = normalizeWSOptions(opts)
	if r.Method != http.MethodGet {
		return nil, fmt.Errorf("websocket: method must be GET")
	}
	if !headerHasToken(r.Header, "Upgrade", "websocket") || !headerHasToken(r.Header, "Connection", "upgrade") {
		return nil, fmt.Errorf("websocket: missing upgrade headers")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, fmt.Errorf("websocket: unsupported version")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		return nil, fmt.Errorf("websocket: missing key")
	}
	if opts.OriginCheck != nil && !opts.OriginCheck(r) {
		return nil, fmt.Errorf("websocket: origin rejected")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("websocket: response writer does not support hijacking")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	accept := computeAccept(key)
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := brw.WriteString(response); err != nil {
		conn.Close()
		return nil, err
	}
	if err := brw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return &WSConn{conn: conn, br: brw.Reader, bw: brw.Writer, role: "server", opts: opts, tlsState: r.TLS}, nil
}

// Dial opens a client WSConn over ws:// or wss://.
func Dial(ctx context.Context, rawURL string, tlsCfg *tls.Config, opts WSOptions) (*WSConn, error) {
	opts = normalizeWSOptions(opts)
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return nil, fmt.Errorf("websocket: unsupported scheme %q", u.Scheme)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "wss" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	var conn net.Conn = raw
	var tlsState *tls.ConnectionState
	if u.Scheme == "wss" {
		tc := tls.Client(raw, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		state := tc.ConnectionState()
		tlsState = &state
		conn = tc
	}
	return upgradeClient(conn, bufio.NewReader(conn), u, host, opts, tlsState, nil)
}

func upgradeClient(conn net.Conn, br *bufio.Reader, u *url.URL, host string, opts WSOptions, tlsState *tls.ConnectionState, trace map[string]string) (*WSConn, error) {
	bw := bufio.NewWriter(conn)

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	uri := u.RequestURI()
	if uri == "" {
		uri = "/"
	}
	req := "GET " + uri + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := bw.WriteString(req); err != nil {
		conn.Close()
		return nil, err
	}
	if err := bw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	if trace != nil {
		trace["upgradeRequest"] = req
	}
	tp := textproto.NewReader(br)
	statusLine, err := tp.ReadLine()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 101") {
		conn.Close()
		return nil, fmt.Errorf("websocket: upgrade failed: %s", statusLine)
	}
	headers, err := tp.ReadMIMEHeader()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if trace != nil {
		var response strings.Builder
		response.WriteString(statusLine + "\r\n")
		_ = http.Header(headers).Write(&response)
		trace["upgradeResponse"] = response.String()
	}
	if got := headers.Get("Sec-WebSocket-Accept"); got != computeAccept(key) {
		conn.Close()
		return nil, fmt.Errorf("websocket: bad accept header")
	}
	return &WSConn{conn: conn, br: br, bw: bw, role: "client", opts: opts, tlsState: tlsState}, nil
}

func (c *WSConn) NetConn() net.Conn { return c.conn }

func (c *WSConn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	if c.opts.ReadTimeout > 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.opts.ReadTimeout))
	}
	var head [2]byte
	if _, err = io.ReadFull(c.br, head[:]); err != nil {
		return
	}
	fin = head[0]&0x80 != 0
	if head[0]&0x70 != 0 {
		return false, 0, nil, fmt.Errorf("websocket: reserved bits set")
	}
	opcode = head[0] & 0x0F
	masked := head[1]&0x80 != 0
	length := int64(head[1] & 0x7F)
	switch length {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(c.br, b[:]); err != nil {
			return
		}
		length = int64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(c.br, b[:]); err != nil {
			return
		}
		length = int64(binary.BigEndian.Uint64(b[:]))
	}
	if length < 0 || length > c.opts.MaxMessageBytes {
		return false, 0, nil, fmt.Errorf("websocket: frame too large (%d)", length)
	}
	if opcode >= wsOpClose && (!fin || length > 125) {
		return false, 0, nil, fmt.Errorf("websocket: invalid control frame")
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(c.br, mask[:]); err != nil {
			return
		}
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(c.br, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	if c.role == "server" && !masked {
		return false, 0, nil, fmt.Errorf("websocket: client frame must be masked")
	}
	if c.role == "client" && masked {
		return false, 0, nil, fmt.Errorf("websocket: server frame must not be masked")
	}
	return
}

// ReadMessage assembles a complete text/binary message, handling ping/pong.
func (c *WSConn) ReadMessage() (opcode byte, payload []byte, err error) {
	var message []byte
	var messageOp byte
	started := false
	for {
		fin, op, part, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch op {
		case wsOpPing:
			_ = c.WriteControl(wsOpPong, part)
			continue
		case wsOpPong:
			continue
		case wsOpClose:
			code := 1000
			reason := ""
			if len(part) >= 2 {
				code = int(binary.BigEndian.Uint16(part[:2]))
				reason = string(part[2:])
			}
			// The caller closes the connection (and sends the close reply),
			// so we do not write a second close frame here.
			return 0, nil, &WSCloseError{Code: code, Reason: reason}
		case wsOpText, wsOpBinary:
			if started {
				return 0, nil, fmt.Errorf("websocket: new data frame before continuation finished")
			}
			messageOp = op
			message = append(message[:0], part...)
			started = true
		case wsOpContinuation:
			if !started {
				return 0, nil, fmt.Errorf("websocket: continuation without start")
			}
			message = append(message, part...)
		default:
			return 0, nil, fmt.Errorf("websocket: unknown opcode %d", op)
		}
		if int64(len(message)) > c.opts.MaxMessageBytes {
			return 0, nil, fmt.Errorf("websocket: message too large")
		}
		if fin {
			if !started {
				return 0, nil, fmt.Errorf("websocket: empty fragmented message")
			}
			if messageOp == wsOpText && !utf8.Valid(message) {
				return 0, nil, fmt.Errorf("websocket: invalid UTF-8 text")
			}
			return messageOp, message, nil
		}
	}
}

func (c *WSConn) writeFrame(fin bool, opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.opts.WriteTimeout > 0 {
		_ = c.conn.SetWriteDeadline(time.Now().Add(c.opts.WriteTimeout))
	}
	first := opcode
	if fin {
		first |= 0x80
	}
	if err := c.bw.WriteByte(first); err != nil {
		return err
	}
	masked := c.role == "client"
	var length byte
	switch {
	case len(payload) < 126:
		length = byte(len(payload))
	case len(payload) <= 65535:
		length = 126
	default:
		length = 127
	}
	if masked {
		length |= 0x80
	}
	if err := c.bw.WriteByte(length); err != nil {
		return err
	}
	switch length & 0x7F {
	case 126:
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(len(payload)))
		if _, err := c.bw.Write(b[:]); err != nil {
			return err
		}
	case 127:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(len(payload)))
		if _, err := c.bw.Write(b[:]); err != nil {
			return err
		}
	}
	if masked {
		var mask [4]byte
		if _, err := rand.Read(mask[:]); err != nil {
			return err
		}
		if _, err := c.bw.Write(mask[:]); err != nil {
			return err
		}
		maskedPayload := make([]byte, len(payload))
		for i := range payload {
			maskedPayload[i] = payload[i] ^ mask[i%4]
		}
		if _, err := c.bw.Write(maskedPayload); err != nil {
			return err
		}
	} else {
		if _, err := c.bw.Write(payload); err != nil {
			return err
		}
	}
	return c.bw.Flush()
}

func (c *WSConn) WriteMessage(opcode byte, payload []byte) error {
	return c.writeFrame(true, opcode, payload)
}

func (c *WSConn) WriteControl(opcode byte, payload []byte) error {
	if len(payload) > 125 {
		payload = payload[:125]
	}
	return c.writeFrame(true, opcode, payload)
}

func (c *WSConn) Ping(payload []byte) error { return c.WriteControl(wsOpPing, payload) }

func (c *WSConn) WriteClose(code int, reason string) error {
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload[:2], uint16(code))
	copy(payload[2:], reason)
	return c.WriteControl(wsOpClose, payload)
}

func (c *WSConn) Close() error {
	var err error
	c.once.Do(func() {
		_ = c.WriteClose(1000, "")
		err = c.conn.Close()
	})
	return err
}

// SetDeadline is used by long-lived readers that want connection-level
// idle timeouts.
func (c *WSConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
