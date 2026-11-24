// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"bufio"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HandshakeError describes an error with the handshake from the peer.
type HandshakeError struct {
	message string
}

func (e HandshakeError) Error() string { return e.message }

// Upgrader specifies parameters for upgrading an HTTP connection to a
// WebSocket connection.
//
// It is safe to call Upgrader's methods concurrently.
type Upgrader struct {
	// HandshakeTimeout specifies the duration for the handshake to complete.
	HandshakeTimeout time.Duration

	// ReadBufferSize and WriteBufferSize specify I/O buffer sizes in bytes. If a buffer
	// size is zero, then buffers allocated by the HTTP server are used. The
	// I/O buffer sizes do not limit the size of the messages that can be sent
	// or received.
	ReadBufferSize, WriteBufferSize int

	// WriteBufferPool is a pool of buffers for write operations. If the value
	// is not set, then write buffers are allocated to the connection for the
	// lifetime of the connection.
	//
	// A pool is most useful when the application has a modest volume of writes
	// across a large number of connections.
	//
	// Applications should use a single pool for each unique value of
	// WriteBufferSize.
	WriteBufferPool BufferPool

	// Subprotocols specifies the server's supported protocols in order of
	// preference. If this field is not nil, then the Upgrade method negotiates a
	// subprotocol by selecting the first match in this list with a protocol
	// requested by the client. If there's no match, then no protocol is
	// negotiated (the Sec-Websocket-Protocol header is not included in the
	// handshake response).
	Subprotocols []string

	// Error specifies the function for generating HTTP error responses. If Error
	// is nil, then http.Error is used to generate the HTTP response.
	Error func(w http.ResponseWriter, r *http.Request, status int, reason error)

	// CheckOrigin returns true if the request Origin header is acceptable. If
	// CheckOrigin is nil, then a safe default is used: return false if the
	// Origin request header is present and the origin host is not equal to
	// request Host header.
	//
	// A CheckOrigin function should carefully validate the request origin to
	// prevent cross-site request forgery.
	CheckOrigin func(r *http.Request) bool

	// EnableCompression specify if the server should attempt to negotiate per
	// message compression (RFC 7692). Setting this value to true does not
	// guarantee that compression will be supported. Currently only "no context
	// takeover" modes are supported.
	//
	// A small compressed message can expand to roughly a thousand times its
	// size. Use Conn.SetReadLimit to bound the size of messages read from
	// the peer.
	EnableCompression bool
}

func (u *Upgrader) returnError(w http.ResponseWriter, r *http.Request, status int, reason string) (*Conn, error) {
	err := HandshakeError{reason}
	if u.Error != nil {
		u.Error(w, r, status, err)
	} else {
		w.Header().Set("Sec-Websocket-Version", "13")
		http.Error(w, http.StatusText(status), status)
	}
	return nil, err
}

// checkSameOrigin returns true if the origin is not set or is equal to the request host.
func checkSameOrigin(r *http.Request) bool {
	origin := r.Header["Origin"]
	if len(origin) == 0 {
		return true
	}
	if len(origin) > 1 || r.Host == "" {
		return false
	}
	u, err := url.Parse(origin[0])
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return false
	}
	return equalASCIIFold(u.Host, r.Host)
}

func (u *Upgrader) selectSubprotocol(r *http.Request, responseHeader http.Header) string {
	if u.Subprotocols != nil {
		clientProtocols := Subprotocols(r)
		for _, clientProtocol := range clientProtocols {
			for _, serverProtocol := range u.Subprotocols {
				if clientProtocol == serverProtocol {
					return clientProtocol
				}
			}
		}
	} else if responseHeader != nil {
		return responseHeader.Get("Sec-Websocket-Protocol")
	}
	return ""
}

// checkCommon validates the parts of the handshake that are common to all HTTP
// versions. On failure, it replies to the client and returns a non-nil error.
func (u *Upgrader) checkCommon(w http.ResponseWriter, r *http.Request, responseHeader http.Header) error {
	checkOrigin := u.CheckOrigin
	if checkOrigin == nil {
		checkOrigin = checkSameOrigin
	}
	var err error
	switch {
	case !tokenListContainsValue(r.Header, "Sec-Websocket-Version", "13"):
		_, err = u.returnError(w, r, http.StatusBadRequest, "websocket: unsupported version: 13 not found in 'Sec-Websocket-Version' header")
	case hasHeaderKey(responseHeader, "Sec-Websocket-Extensions"):
		_, err = u.returnError(w, r, http.StatusInternalServerError, "websocket: application specific 'Sec-WebSocket-Extensions' headers are unsupported")
	case !checkOrigin(r):
		_, err = u.returnError(w, r, http.StatusForbidden, "websocket: request origin not allowed by Upgrader.CheckOrigin")
	}
	return err
}

// negotiateCompression reports whether permessage-deflate (RFC 7692) should
// be used on the connection.
func (u *Upgrader) negotiateCompression(r *http.Request) bool {
	if u.EnableCompression {
		for _, ext := range parseExtensions(r.Header) {
			if ext[""] == "permessage-deflate" {
				return true
			}
		}
	}
	return false
}

func hasHeaderKey(h http.Header, key string) bool {
	for k := range h {
		if equalASCIIFold(k, key) {
			return true
		}
	}
	return false
}

// isReservedResponseHeader reports whether k is a response header that the
// application must not set because Upgrade sets it or it is specific to
// HTTP/1.1 connection management.
func isReservedResponseHeader(k string) bool {
	return equalASCIIFold(k, "Sec-Websocket-Protocol") ||
		equalASCIIFold(k, "Sec-Websocket-Accept") ||
		equalASCIIFold(k, "Connection") ||
		equalASCIIFold(k, "Keep-Alive") ||
		equalASCIIFold(k, "Proxy-Connection") ||
		equalASCIIFold(k, "Transfer-Encoding") ||
		equalASCIIFold(k, "Upgrade")
}

// Upgrade upgrades the HTTP server connection to the WebSocket protocol.
//
// Upgrade supports HTTP/1.1 GET handshakes (RFC 6455) as well as HTTP/2
// (RFC 8441) and HTTP/3 (RFC 9220) Extended CONNECT handshakes. For Go's
// net/http HTTP/2 server, Extended CONNECT must be enabled via
// http.HTTP2Config.EnableConnectProtocol (Go 1.28+) or GODEBUG=http2xconnect=1
// / github.com/c2FmZQ/websocket/h2xconnect (Go 1.24–1.27).
//
// Unlike HTTP/1.1, an HTTP/2 or HTTP/3 WebSocket connection lives on the
// handler's http.ResponseWriter, which is only valid until the handler
// returns. The handler must call Conn.Close before returning; Serve does this
// automatically. After Close returns, the connection never uses the
// ResponseWriter again and its methods return net.ErrClosed, so goroutines
// that still hold the connection are safe. Returning from the handler without
// calling Close while another goroutine uses the connection is a data race
// with the HTTP server.
//
// Any http.ResponseWriter middleware must implement
// Unwrap() http.ResponseWriter so that http.ResponseController can manage
// stream deadlines and flushing; otherwise Upgrade fails with
// http.StatusInternalServerError for HTTP/2 and HTTP/3 requests.
//
// The responseHeader is included in the response to the client's upgrade
// request. Use the responseHeader to specify cookies (Set-Cookie). To specify
// subprotocols supported by the server, set Upgrader.Subprotocols directly.
//
// If the upgrade fails, then Upgrade replies to the client with an HTTP error
// response.
func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (*Conn, error) {
	if r.ProtoMajor >= 2 {
		return u.upgradeExtendedConnect(w, r, responseHeader)
	}
	const badHandshake = "websocket: the client is not using the websocket protocol: "

	if !tokenListContainsValue(r.Header, "Connection", "upgrade") {
		return u.returnError(w, r, http.StatusBadRequest, badHandshake+"'upgrade' token not found in 'Connection' header")
	}

	if !tokenListContainsValue(r.Header, "Upgrade", "websocket") {
		w.Header().Set("Upgrade", "websocket")
		return u.returnError(w, r, http.StatusUpgradeRequired, badHandshake+"'websocket' token not found in 'Upgrade' header")
	}

	if r.Method != http.MethodGet {
		return u.returnError(w, r, http.StatusMethodNotAllowed, badHandshake+"request method is not GET")
	}

	if err := u.checkCommon(w, r, responseHeader); err != nil {
		return nil, err
	}

	challengeKey := r.Header.Get("Sec-Websocket-Key")
	if !isValidChallengeKey(challengeKey) {
		return u.returnError(w, r, http.StatusBadRequest, "websocket: not a websocket handshake: 'Sec-WebSocket-Key' header must be Base64 encoded value of 16-byte in length")
	}

	subprotocol := u.selectSubprotocol(r, responseHeader)
	compress := u.negotiateCompression(r)

	netConn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return u.returnError(w, r, http.StatusInternalServerError,
			"websocket: hijack: "+err.Error())
	}

	// Close the network connection when returning an error. The variable
	// netConn is set to nil before the success return at the end of the
	// function.
	defer func() {
		if netConn != nil {
			// It's safe to ignore the error from Close() because this code is
			// only executed when returning a more important error to the
			// application.
			_ = netConn.Close()
		}
	}()

	var br *bufio.Reader
	if u.ReadBufferSize == 0 && brw.Reader.Size() > 256 {
		// Use hijacked buffered reader as the connection reader.
		br = brw.Reader
	} else if brw.Reader.Buffered() > 0 {
		// Wrap the network connection to read buffered data in brw.Reader
		// before reading from the network connection. This should be rare
		// because a client must not send message data before receiving the
		// handshake response.
		netConn = &brNetConn{br: brw.Reader, Conn: netConn}
	}

	buf := brw.Writer.AvailableBuffer()

	var writeBuf []byte
	if u.WriteBufferPool == nil && u.WriteBufferSize == 0 && len(buf) >= maxFrameHeaderSize+256 {
		// Reuse hijacked write buffer as connection buffer.
		writeBuf = buf
	}

	c := newConn(netConn, true, u.ReadBufferSize, u.WriteBufferSize, u.WriteBufferPool, br, writeBuf)
	c.subprotocol = subprotocol

	if compress {
		c.newCompressionWriter = compressNoContextTakeover
		c.newDecompressionReader = decompressNoContextTakeover
	}

	// Use larger of hijacked buffer and connection write buffer for header.
	p := buf
	if len(c.writeBuf) > len(p) {
		p = c.writeBuf
	}
	p = p[:0]

	p = append(p, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "...)
	p = append(p, computeAcceptKey(challengeKey)...)
	p = append(p, "\r\n"...)
	if c.subprotocol != "" {
		p = append(p, "Sec-WebSocket-Protocol: "...)
		for i := 0; i < len(c.subprotocol); i++ {
			b := c.subprotocol[i]
			if b <= 31 {
				// prevent response splitting.
				b = ' '
			}
			p = append(p, b)
		}
		p = append(p, "\r\n"...)
	}
	if compress {
		p = append(p, "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n"...)
	}
	for k, vs := range responseHeader {
		if isReservedResponseHeader(k) {
			continue
		}
		for _, v := range vs {
			for i := 0; i < len(k); i++ {
				b := k[i]
				if b <= 31 || b == ':' {
					b = '-'
				}
				p = append(p, b)
			}
			p = append(p, ": "...)
			for i := 0; i < len(v); i++ {
				b := v[i]
				if b <= 31 {
					// prevent response splitting.
					b = ' '
				}
				p = append(p, b)
			}
			p = append(p, "\r\n"...)
		}
	}
	p = append(p, "\r\n"...)

	if u.HandshakeTimeout > 0 {
		if err := netConn.SetWriteDeadline(time.Now().Add(u.HandshakeTimeout)); err != nil {
			return nil, err
		}
	} else {
		// Clear deadlines set by HTTP server.
		if err := netConn.SetDeadline(time.Time{}); err != nil {
			return nil, err
		}
	}

	if _, err = netConn.Write(p); err != nil {
		return nil, err
	}
	if u.HandshakeTimeout > 0 {
		if err := netConn.SetWriteDeadline(time.Time{}); err != nil {
			return nil, err
		}
	}

	// Success! Set netConn to nil to stop the deferred function above from
	// closing the network connection.
	netConn = nil

	return c, nil
}

// Serve upgrades the HTTP server connection to the WebSocket protocol, calls f
// with the connection, and closes the connection when f returns. Call Serve
// from an HTTP handler and return from the handler when Serve returns. This
// enforces the connection lifetime required by HTTP/2 and HTTP/3 (see
// Upgrade) and works the same way over HTTP/1.1.
//
// f must keep running for as long as the connection is in use. Goroutines
// started by f may keep using the connection after f returns, in which case
// their calls fail with net.ErrClosed.
//
// If the upgrade fails, Serve replies to the client with an HTTP error
// response and returns the error without calling f.
func (u *Upgrader) Serve(w http.ResponseWriter, r *http.Request, responseHeader http.Header, f func(*Conn)) error {
	c, err := u.Upgrade(w, r, responseHeader)
	if err != nil {
		return err
	}
	defer c.Close()
	f(c)
	return nil
}

// Upgrade upgrades the HTTP server connection to the WebSocket protocol.
//
// Deprecated: Use websocket.Upgrader instead.
//
// Upgrade does not perform origin checking. The application is responsible for
// checking the Origin header before calling Upgrade. An example implementation
// of the same origin policy check is:
//
//	if req.Header.Get("Origin") != "http://"+req.Host {
//		http.Error(w, "Origin not allowed", http.StatusForbidden)
//		return
//	}
//
// If the endpoint supports subprotocols, then the application is responsible
// for negotiating the protocol used on the connection. Use the Subprotocols()
// function to get the subprotocols requested by the client. Use the
// Sec-Websocket-Protocol response header to specify the subprotocol selected
// by the application.
//
// The responseHeader is included in the response to the client's upgrade
// request. Use the responseHeader to specify cookies (Set-Cookie) and the
// negotiated subprotocol (Sec-Websocket-Protocol).
//
// The connection buffers IO to the underlying network connection. The
// readBufSize and writeBufSize parameters specify the size of the buffers to
// use. Messages can be larger than the buffers.
//
// If the request is not a valid WebSocket handshake, then Upgrade returns an
// error of type HandshakeError. Applications should handle this error by
// replying to the client with an HTTP error response.
func Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header, readBufSize, writeBufSize int) (*Conn, error) {
	u := Upgrader{ReadBufferSize: readBufSize, WriteBufferSize: writeBufSize}
	u.Error = func(w http.ResponseWriter, r *http.Request, status int, reason error) {
		// don't return errors to maintain backwards compatibility
	}
	u.CheckOrigin = func(r *http.Request) bool {
		// allow all connections by default
		return true
	}
	return u.Upgrade(w, r, responseHeader)
}

// Subprotocols returns the subprotocols requested by the client in the
// Sec-Websocket-Protocol header.
func Subprotocols(r *http.Request) []string {
	h := strings.TrimSpace(r.Header.Get("Sec-Websocket-Protocol"))
	if h == "" {
		return nil
	}
	protocols := strings.Split(h, ",")
	for i := range protocols {
		protocols[i] = strings.TrimSpace(protocols[i])
	}
	return protocols
}

// IsWebSocketUpgrade returns true if the client requested upgrade to the
// WebSocket protocol over HTTP/1.1 (Upgrade: websocket) or HTTP/2 / HTTP/3
// Extended CONNECT (:protocol = websocket).
func IsWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.ProtoMajor >= 2 {
		proto, ok := extendedConnectProtocol(r)
		return r.Method == http.MethodConnect && ok && equalASCIIFold(proto, "websocket")
	}
	return tokenListContainsValue(r.Header, "Connection", "upgrade") &&
		tokenListContainsValue(r.Header, "Upgrade", "websocket")
}

type brNetConn struct {
	br *bufio.Reader
	net.Conn
}

func (b *brNetConn) Read(p []byte) (n int, err error) {
	if b.br != nil {
		// Limit read to buferred data.
		if n := b.br.Buffered(); len(p) > n {
			p = p[:n]
		}
		n, err = b.br.Read(p)
		if b.br.Buffered() == 0 {
			b.br = nil
		}
		return n, err
	}
	return b.Conn.Read(p)
}

// NetConn returns the underlying connection that is wrapped by b.
func (b *brNetConn) NetConn() net.Conn {
	return b.Conn
}
