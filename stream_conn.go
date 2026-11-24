// Copyright 2026 Robin Thellend <rthellend@rthellend.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
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
	if proto, ok := extendedConnectProtocol(r); !ok || !equalASCIIFold(proto, "websocket") {
		return u.returnError(w, r, http.StatusBadRequest, badHandshake+"':protocol' header must be 'websocket'")
	}
	if err := u.checkCommon(w, r, responseHeader); err != nil {
		return nil, err
	}

	// streamNetConn needs stream deadlines to implement timeouts and to
	// unblock a pending write in Close. Without them, a peer that stops
	// reading could block the connection forever. Deadlines are unavailable
	// when middleware wraps the ResponseWriter without implementing
	// Unwrap() http.ResponseWriter.
	rc := http.NewResponseController(w)
	var handshakeDeadline time.Time
	if u.HandshakeTimeout > 0 {
		handshakeDeadline = time.Now().Add(u.HandshakeTimeout)
	}
	// Clear the read deadline set by the HTTP server, like Hijack does for
	// HTTP/1.1.
	if err := errors.Join(rc.SetReadDeadline(time.Time{}), rc.SetWriteDeadline(handshakeDeadline)); err != nil {
		return u.returnError(w, r, http.StatusInternalServerError, "websocket: response writer does not support deadlines: "+err.Error())
	}

	subprotocol := u.selectSubprotocol(r, responseHeader)
	compress := u.negotiateCompression(r)

	if subprotocol != "" {
		w.Header().Set("Sec-WebSocket-Protocol", subprotocol)
	}
	if compress {
		w.Header().Set("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover; client_no_context_takeover")
	}
	for k, vs := range responseHeader {
		if isReservedResponseHeader(k) {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return nil, err
	}
	if !handshakeDeadline.IsZero() {
		if err := rc.SetWriteDeadline(time.Time{}); err != nil {
			return nil, err
		}
	}

	c := newConn(newStreamNetConn(w, r), true, u.ReadBufferSize, u.WriteBufferSize, u.WriteBufferPool, nil, nil)
	c.subprotocol = subprotocol
	if compress {
		c.newCompressionWriter = compressNoContextTakeover
		c.newDecompressionReader = decompressNoContextTakeover
	}
	return c, nil
}

// streamNetConn adapts an HTTP/2 or HTTP/3 request/response stream to net.Conn.
//
// The ResponseWriter is only valid until the handler returns, so the handler
// must call Close before returning. After Close returns, w and rc are never
// used again.
//
// Using w after the handler returned is a data race with the HTTP server that
// this type cannot prevent. As a last resort, the panics that Go's HTTP/2
// server raises in that case are turned into net.ErrClosed.
//
// Lock order: Conn.mu -> writeMu -> mu.
type streamNetConn struct {
	r          io.ReadCloser
	w          http.ResponseWriter
	rc         *http.ResponseController
	localAddr  net.Addr
	remoteAddr net.Addr

	writeMu sync.Mutex // held for the duration of a write

	mu            sync.Mutex
	writeDeadline time.Time
	writing       bool
	closed        bool

	closeOnce sync.Once
	closeErr  error
}

var (
	_ net.Conn      = (*streamNetConn)(nil)
	_ buffersWriter = (*streamNetConn)(nil)
)

func newStreamNetConn(w http.ResponseWriter, r *http.Request) *streamNetConn {
	s := &streamNetConn{
		r:          r.Body,
		w:          w,
		rc:         http.NewResponseController(w),
		localAddr:  &net.TCPAddr{},
		remoteAddr: stringAddr(r.RemoteAddr),
	}
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && a != nil {
		s.localAddr = a
	}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		s.remoteAddr = net.TCPAddrFromAddrPort(ap)
	}
	return s
}

// call runs f, which uses w or rc, and converts a panic into net.ErrClosed.
// Go's HTTP/2 server panics when a ResponseWriter is used after its handler
// returned, which would otherwise crash the process.
func call(f func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = net.ErrClosed
		}
	}()
	return f()
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

	// HTTP/2 and HTTP/3 reset the stream when a write deadline expires, even
	// if no write is in progress. The deadline is therefore only armed for
	// the duration of each write.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	deadline := s.writeDeadline
	if !deadline.IsZero() {
		if deadline.Before(time.Now()) {
			s.mu.Unlock()
			return os.ErrDeadlineExceeded
		}
		if err := call(func() error { return s.rc.SetWriteDeadline(deadline) }); err != nil {
			s.mu.Unlock()
			return err
		}
	}
	s.writing = true
	s.mu.Unlock()

	err := call(func() error {
		for _, buf := range bufs {
			if _, err := s.w.Write(buf); err != nil {
				return err
			}
		}
		return s.rc.Flush()
	})

	s.mu.Lock()
	s.writing = false
	if !deadline.IsZero() && !s.closed {
		_ = call(func() error { return s.rc.SetWriteDeadline(time.Time{}) })
	}
	s.mu.Unlock()
	return err
}

func (s *streamNetConn) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		if s.writing {
			// Abort the pending write.
			_ = call(func() error { return s.rc.SetWriteDeadline(time.Unix(1, 0)) })
		}
		s.closed = true
		s.mu.Unlock()

		s.closeErr = s.r.Close()

		// Wait for a pending write to finish.
		s.writeMu.Lock()
		s.writeMu.Unlock()
	})
	return s.closeErr
}

func (s *streamNetConn) LocalAddr() net.Addr  { return s.localAddr }
func (s *streamNetConn) RemoteAddr() net.Addr { return s.remoteAddr }

func (s *streamNetConn) SetDeadline(t time.Time) error {
	return errors.Join(s.SetReadDeadline(t), s.SetWriteDeadline(t))
}

func (s *streamNetConn) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	return call(func() error { return s.rc.SetReadDeadline(t) })
}

func (s *streamNetConn) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.writeDeadline = t
	if s.writing && !t.IsZero() && t.Before(time.Now()) {
		// Abort the pending write.
		return call(func() error { return s.rc.SetWriteDeadline(t) })
	}
	return nil
}
