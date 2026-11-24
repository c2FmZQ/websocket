// Copyright 2026 Robin Thellend <rthellend@rthellend.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type buffersWriter interface {
	writeBuffers(bufs [][]byte) error
}

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

func parseIPZone(s string) (net.IP, string) {
	ipStr, zone, _ := strings.Cut(s, "%")
	return net.ParseIP(ipStr), zone
}

func parseRemoteAddr(addr string) net.Addr {
	if host, portStr, err := net.SplitHostPort(addr); err == nil {
		if ip, zone := parseIPZone(host); ip != nil {
			port, _ := strconv.Atoi(portStr)
			return &net.TCPAddr{IP: ip, Port: port, Zone: zone}
		}
	}
	if ip, zone := parseIPZone(addr); ip != nil {
		return &net.TCPAddr{IP: ip, Zone: zone}
	}
	return stringAddr(addr)
}

func localAddrFromRequest(r *http.Request) net.Addr {
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && a != nil {
		return a
	}
	return &net.TCPAddr{}
}

// extendedConnectProtocol extracts the Extended CONNECT :protocol token from an
// HTTP/2 (RFC 8441) or HTTP/3 (RFC 9220) request.
//
// Go's net/http HTTP/2 server stores :protocol in r.Header[":protocol"], while
// quic-go/http3 removes ":protocol" from r.Header and stores the protocol token
// in r.Proto (setting r.Proto to "HTTP/3.0" when :protocol is absent).
func extendedConnectProtocol(r *http.Request) (string, bool) {
	if protos, ok := r.Header[":protocol"]; ok {
		if len(protos) != 1 || protos[0] == "" {
			return "", false
		}
		return protos[0], true
	}
	if r.ProtoMajor == 3 && r.Proto != "" && !strings.HasPrefix(r.Proto, "HTTP/") {
		return r.Proto, true
	}
	return "", false
}

func isForbiddenExtendedConnectRespHeader(k string) bool {
	return equalASCIIFold(k, "Sec-Websocket-Protocol") ||
		equalASCIIFold(k, "Connection") ||
		equalASCIIFold(k, "Keep-Alive") ||
		equalASCIIFold(k, "Proxy-Connection") ||
		equalASCIIFold(k, "Transfer-Encoding") ||
		equalASCIIFold(k, "Upgrade")
}

func (u *Upgrader) upgradeExtendedConnect(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (*Conn, error) {
	const badHandshake = "websocket: the client is not using the websocket protocol: "

	if r.ProtoMajor != 2 && r.ProtoMajor != 3 {
		return u.returnError(w, r, http.StatusHTTPVersionNotSupported, "websocket: unsupported HTTP version")
	}
	if r.Method != http.MethodConnect {
		w.Header().Set("Allow", http.MethodConnect)
		return u.returnError(w, r, http.StatusMethodNotAllowed, badHandshake+"request method is not CONNECT")
	}
	if r.Host == "" || strings.Contains(r.Host, "@") {
		return u.returnError(w, r, http.StatusBadRequest, badHandshake+"missing or invalid ':authority' header")
	}
	proto, ok := extendedConnectProtocol(r)
	if !ok || !equalASCIIFold(proto, "websocket") {
		return u.returnError(w, r, http.StatusBadRequest, badHandshake+"':protocol' header must be 'websocket'")
	}
	if !tokenListContainsValue(r.Header, "Sec-Websocket-Version", "13") {
		return u.returnError(w, r, http.StatusBadRequest, "websocket: unsupported version: 13 not found in 'Sec-Websocket-Version' header")
	}
	if _, ok := responseHeader["Sec-Websocket-Extensions"]; ok {
		return u.returnError(w, r, http.StatusInternalServerError, "websocket: application specific 'Sec-WebSocket-Extensions' headers are unsupported")
	}

	checkOrigin := u.CheckOrigin
	if checkOrigin == nil {
		checkOrigin = checkSameOrigin
	}
	if !checkOrigin(r) {
		return u.returnError(w, r, http.StatusForbidden, "websocket: request origin not allowed by Upgrader.CheckOrigin")
	}

	subprotocol := u.selectSubprotocol(r, responseHeader)

	var compress bool
	if u.EnableCompression {
		for _, ext := range parseExtensions(r.Header) {
			if ext[""] != "permessage-deflate" {
				continue
			}
			compress = true
			break
		}
	}

	if subprotocol != "" {
		w.Header().Set("Sec-WebSocket-Protocol", subprotocol)
	}
	if compress {
		w.Header().Set("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover; client_no_context_takeover")
	}
	for k, vs := range responseHeader {
		if isForbiddenExtendedConnectRespHeader(k) {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex()

	if u.HandshakeTimeout > 0 {
		if err := rc.SetWriteDeadline(time.Now().Add(u.HandshakeTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return nil, err
		}
	}
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return nil, err
	}
	if u.HandshakeTimeout > 0 {
		if err := rc.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return nil, err
		}
	}

	sc := newStreamNetConn(r.Body, w, rc, localAddrFromRequest(r), parseRemoteAddr(r.RemoteAddr))
	c := newConn(sc, true, u.ReadBufferSize, u.WriteBufferSize, u.WriteBufferPool, nil, nil)
	c.subprotocol = subprotocol
	if compress {
		c.newCompressionWriter = compressNoContextTakeover
		c.newDecompressionReader = decompressNoContextTakeover
	}
	return c, nil
}

// streamNetConn adapts an HTTP/2 or HTTP/3 request/response stream to net.Conn.
//
// Lock order: Conn.mu -> writeMu -> rcMu (short non-blocking mutex).
// Once Close() returns, closed is true and neither w nor rc will ever be
// accessed again, allowing the caller's ServeHTTP handler to return safely.
type streamNetConn struct {
	r          io.ReadCloser
	w          http.ResponseWriter
	rc         *http.ResponseController
	localAddr  net.Addr
	remoteAddr net.Addr

	deadlineMu    sync.Mutex
	writeDeadline time.Time

	writeMu sync.Mutex

	rcMu     sync.Mutex
	writing  bool
	closed   bool
	writeErr error

	closeOnce sync.Once
	closeErr  error
}

var (
	_ net.Conn      = (*streamNetConn)(nil)
	_ buffersWriter = (*streamNetConn)(nil)
)

func newStreamNetConn(r io.ReadCloser, w http.ResponseWriter, rc *http.ResponseController, localAddr, remoteAddr net.Addr) *streamNetConn {
	return &streamNetConn{
		r:          r,
		w:          w,
		rc:         rc,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

func (s *streamNetConn) Read(p []byte) (int, error) {
	return s.r.Read(p)
}

func (s *streamNetConn) Write(p []byte) (int, error) {
	if err := s.writeBuffers([][]byte{p}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *streamNetConn) writeBuffers(bufs [][]byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	deadline := s.getWriteDeadline()

	s.rcMu.Lock()
	if s.closed {
		s.rcMu.Unlock()
		return net.ErrClosed
	}
	if s.writeErr != nil {
		err := s.writeErr
		s.rcMu.Unlock()
		return err
	}
	armedDeadline := false
	if !deadline.IsZero() {
		if deadline.Before(time.Now()) {
			s.rcMu.Unlock()
			return os.ErrDeadlineExceeded
		}
		if err := s.rc.SetWriteDeadline(deadline); err != nil {
			if !errors.Is(err, http.ErrNotSupported) {
				s.writeErr = err
				s.rcMu.Unlock()
				return err
			}
		} else {
			armedDeadline = true
		}
	}
	s.writing = true
	s.rcMu.Unlock()

	var writeErr error
	for _, buf := range bufs {
		if len(buf) == 0 {
			continue
		}
		if _, err := s.w.Write(buf); err != nil {
			writeErr = err
			break
		}
	}
	if writeErr == nil {
		if err := s.rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			writeErr = err
		}
	}

	s.rcMu.Lock()
	s.writing = false
	if writeErr != nil {
		if s.writeErr == nil {
			s.writeErr = writeErr
		}
	} else if armedDeadline && !s.closed {
		_ = s.rc.SetWriteDeadline(time.Time{})
	}
	s.rcMu.Unlock()

	return writeErr
}

func (s *streamNetConn) Close() error {
	s.closeOnce.Do(func() {
		s.rcMu.Lock()
		s.closed = true
		_ = s.rc.SetReadDeadline(time.Time{})
		if s.writing {
			_ = s.rc.SetWriteDeadline(time.Unix(1, 0))
		}
		s.rcMu.Unlock()

		s.closeErr = s.r.Close()

		s.writeMu.Lock()
		s.writeMu.Unlock()
	})
	return s.closeErr
}

func (s *streamNetConn) LocalAddr() net.Addr  { return s.localAddr }
func (s *streamNetConn) RemoteAddr() net.Addr { return s.remoteAddr }

func (s *streamNetConn) SetDeadline(t time.Time) error {
	err1 := s.SetReadDeadline(t)
	err2 := s.SetWriteDeadline(t)
	if err1 != nil {
		return err1
	}
	return err2
}

func (s *streamNetConn) SetReadDeadline(t time.Time) error {
	s.rcMu.Lock()
	defer s.rcMu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	err := s.rc.SetReadDeadline(t)
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}

func (s *streamNetConn) SetWriteDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.writeDeadline = t
	s.deadlineMu.Unlock()

	s.rcMu.Lock()
	defer s.rcMu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if !t.IsZero() && t.Before(time.Now()) && s.writing {
		if err := s.rc.SetWriteDeadline(t); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return err
		}
	}
	return nil
}

func (s *streamNetConn) getWriteDeadline() time.Time {
	s.deadlineMu.Lock()
	t := s.writeDeadline
	s.deadlineMu.Unlock()
	return t
}
