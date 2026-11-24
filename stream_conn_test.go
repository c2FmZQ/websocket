// Copyright 2026 Robin Thellend <rthellend@rthellend.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func buildTestFrame(fin bool, opcode byte, rsv byte, masked bool, payload []byte) []byte {
	var b bytes.Buffer
	b0 := opcode | (rsv & 0x70)
	if fin {
		b0 |= 0x80
	}
	b.WriteByte(b0)

	var maskBit byte
	if masked {
		maskBit = 0x80
	}
	n := len(payload)
	switch {
	case n < 126:
		b.WriteByte(maskBit | byte(n))
	case n <= 65535:
		b.WriteByte(maskBit | 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		b.Write(ext[:])
	default:
		b.WriteByte(maskBit | 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		b.Write(ext[:])
	}

	if masked {
		mask := [4]byte{0x12, 0x34, 0x56, 0x78}
		b.Write(mask[:])
		maskedPayload := make([]byte, n)
		for i := range payload {
			maskedPayload[i] = payload[i] ^ mask[i&3]
		}
		b.Write(maskedPayload)
	} else {
		b.Write(payload)
	}
	return b.Bytes()
}

func readTestServerFrame(r io.Reader) (fin bool, opcode byte, rsv byte, payload []byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return false, 0, 0, nil, err
	}
	fin = hdr[0]&0x80 != 0
	rsv = hdr[0] & 0x70
	opcode = hdr[0] & 0x0f
	if hdr[1]&0x80 != 0 {
		return false, 0, 0, nil, errors.New("unexpected masked server frame")
	}
	n := int(hdr[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return false, 0, 0, nil, err
		}
		n = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return false, 0, 0, nil, err
		}
		n = int(binary.BigEndian.Uint64(ext[:]))
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return false, 0, 0, nil, err
	}
	return fin, opcode, rsv, payload, nil
}

type mockStreamResponseWriter struct {
	header        http.Header
	status        int
	pw            *io.PipeWriter
	mu            sync.Mutex
	readDead      time.Time
	writeDead     time.Time
	flushes       int
	wroteHeader   bool
	handlerExited atomic.Bool
}

func newMockStreamResponseWriter(pw *io.PipeWriter) *mockStreamResponseWriter {
	return &mockStreamResponseWriter{
		header: make(http.Header),
		pw:     pw,
	}
}

func (w *mockStreamResponseWriter) checkActive() {
	if w.handlerExited.Load() {
		panic("ResponseWriter/ResponseController used after handler exited")
	}
}

func (w *mockStreamResponseWriter) Header() http.Header { w.checkActive(); return w.header }

func (w *mockStreamResponseWriter) WriteHeader(statusCode int) {
	w.checkActive()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.wroteHeader {
		w.status = statusCode
		w.wroteHeader = true
	}
}

func (w *mockStreamResponseWriter) Write(p []byte) (int, error) {
	w.checkActive()
	w.WriteHeader(http.StatusOK)
	return w.pw.Write(p)
}

func (w *mockStreamResponseWriter) FlushError() error {
	w.checkActive()
	w.mu.Lock()
	w.flushes++
	w.mu.Unlock()
	return nil
}

func (w *mockStreamResponseWriter) Flush() { _ = w.FlushError() }

func (w *mockStreamResponseWriter) SetReadDeadline(t time.Time) error {
	w.checkActive()
	w.mu.Lock()
	w.readDead = t
	w.mu.Unlock()
	return nil
}

func (w *mockStreamResponseWriter) SetWriteDeadline(t time.Time) error {
	w.checkActive()
	w.mu.Lock()
	w.writeDead = t
	if !t.IsZero() && t.Before(time.Now()) {
		_ = w.pw.CloseWithError(os.ErrDeadlineExceeded)
	}
	w.mu.Unlock()
	return nil
}

func TestIsWebSocketUpgradeExtendedConnect(t *testing.T) {
	if IsWebSocketUpgrade(nil) {
		t.Fatal("IsWebSocketUpgrade(nil) = true, want false")
	}

	// HTTP/2 style (:protocol header)
	h2Req, _ := http.NewRequest(http.MethodConnect, "https://example.com/ws", nil)
	h2Req.ProtoMajor = 2
	h2Req.Header.Set(":protocol", "websocket")
	if !IsWebSocketUpgrade(h2Req) {
		t.Fatal("expected HTTP/2 Extended CONNECT request to match")
	}

	// HTTP/3 quic-go style (r.Proto = "websocket", no :protocol in Header)
	h3Req, _ := http.NewRequest(http.MethodConnect, "https://example.com/ws", nil)
	h3Req.ProtoMajor = 3
	h3Req.Proto = "websocket"
	if !IsWebSocketUpgrade(h3Req) {
		t.Fatal("expected HTTP/3 quic-go Extended CONNECT request to match")
	}

	// Regular HTTP/3 CONNECT without :protocol (r.Proto = "HTTP/3.0")
	h3Plain, _ := http.NewRequest(http.MethodConnect, "https://example.com", nil)
	h3Plain.ProtoMajor = 3
	h3Plain.Proto = "HTTP/3.0"
	if IsWebSocketUpgrade(h3Plain) {
		t.Fatal("expected plain HTTP/3 CONNECT without :protocol to return false")
	}
}

func TestExtendedConnectH2AndH3StreamFeatures(t *testing.T) {
	for _, protoMajor := range []int{2, 3} {
		name := fmt.Sprintf("HTTP_%d", protoMajor)
		t.Run(name, func(t *testing.T) {
			cr, cw := io.Pipe()
			sr, sw := io.Pipe()
			defer cr.Close()
			defer cw.Close()
			defer sr.Close()
			defer sw.Close()

			upgrader := Upgrader{
				Subprotocols:      []string{"chat.v2", "chat.v1"},
				EnableCompression: true,
				WriteBufferSize:   32,
			}

			req, _ := http.NewRequest(http.MethodConnect, "https://example.com/ws", cr)
			req.ProtoMajor = protoMajor
			req.Host = "example.com"
			req.RemoteAddr = "[fe80::1%eth0]:54321"
			req.Header = http.Header{
				"Sec-Websocket-Version":    {"13"},
				"Sec-Websocket-Protocol":   {"chat.v1"},
				"Sec-Websocket-Extensions": {"permessage-deflate; client_no_context_takeover"},
				"Origin":                   {"https://example.com"},
			}
			if protoMajor == 2 {
				req.Proto = "HTTP/2.0"
				req.Header[":protocol"] = []string{"websocket"}
			} else {
				req.Proto = "websocket" // quic-go/http3 convention
			}

			mw := newMockStreamResponseWriter(sw)
			conn, err := upgrader.Upgrade(mw, req, http.Header{
				"X-Custom":   {"ok"},
				"Connection": {"keep-alive"},
			})
			if err != nil {
				t.Fatalf("Upgrade: %v", err)
			}
			defer func() {
				_ = conn.Close()
				mw.handlerExited.Store(true)
			}()

			if conn.Subprotocol() != "chat.v1" || mw.Header().Get("Sec-WebSocket-Protocol") != "chat.v1" {
				t.Fatalf("subprotocol = %q / %q", conn.Subprotocol(), mw.Header().Get("Sec-WebSocket-Protocol"))
			}
			if !strings.Contains(mw.Header().Get("Sec-WebSocket-Extensions"), "permessage-deflate") {
				t.Fatalf("expected permessage-deflate extension header, got %q", mw.Header().Get("Sec-WebSocket-Extensions"))
			}
			if mw.Header().Get("X-Custom") != "ok" || mw.Header().Get("Connection") != "" {
				t.Fatalf("unexpected headers: %+v", mw.Header())
			}
			tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
			if !ok || tcpAddr.Zone != "eth0" || tcpAddr.Port != 54321 {
				t.Fatalf("RemoteAddr = %#v", conn.RemoteAddr())
			}

			// Verify clientConn <-> serverConn round-trip (including permessage-deflate compression & single-flush large writes!)
			clientConn := newConn(&rwcNetConn{r: sr, w: cw}, false, 1024, 1024, nil, nil, nil)
			clientConn.newCompressionWriter = compressNoContextTakeover
			clientConn.newDecompressionReader = decompressNoContextTakeover
			defer clientConn.Close()

			payload := bytes.Repeat([]byte("compressible-payload-1234567890-"), 100)
			clientDone := make(chan error, 1)
			go func() {
				if err := clientConn.WriteMessage(BinaryMessage, payload); err != nil {
					clientDone <- err
					return
				}
				mt, echoed, err := clientConn.ReadMessage()
				if err != nil {
					clientDone <- err
					return
				}
				if mt != BinaryMessage || !bytes.Equal(echoed, payload) {
					clientDone <- fmt.Errorf("mismatch: mt=%d len=%d", mt, len(echoed))
					return
				}
				clientDone <- nil
			}()

			mt, got, err := conn.ReadMessage()
			if err != nil || mt != BinaryMessage || !bytes.Equal(got, payload) {
				t.Fatalf("server ReadMessage = (%d, len=%d, %v)", mt, len(got), err)
			}

			mw.mu.Lock()
			flushesBefore := mw.flushes
			mw.mu.Unlock()

			// Disable write compression for one large message to verify writeBuffers flushes once (not twice).
			conn.EnableWriteCompression(false)
			if err := conn.WriteMessage(BinaryMessage, payload); err != nil {
				t.Fatalf("server WriteMessage: %v", err)
			}
			mw.mu.Lock()
			flushesDelta := mw.flushes - flushesBefore
			mw.mu.Unlock()
			if flushesDelta != 1 {
				t.Fatalf("flushes for large unbuffered frame = %d, want 1", flushesDelta)
			}

			if err := <-clientDone; err != nil {
				t.Fatalf("client round-trip: %v", err)
			}
		})
	}
}

func newTestStreamNetConn(w http.ResponseWriter, body io.ReadCloser) *streamNetConn {
	r, _ := http.NewRequest(http.MethodConnect, "https://localhost/ws", body)
	return newStreamNetConn(w, r)
}

type rwcNetConn struct {
	r io.ReadCloser
	w io.WriteCloser
}

func (c *rwcNetConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *rwcNetConn) Write(p []byte) (int, error)        { return c.w.Write(p) }
func (c *rwcNetConn) Close() error                       { _ = c.r.Close(); return c.w.Close() }
func (c *rwcNetConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *rwcNetConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *rwcNetConn) SetDeadline(t time.Time) error      { return nil }
func (c *rwcNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *rwcNetConn) SetWriteDeadline(t time.Time) error { return nil }

func TestExtendedConnectValidationAndCloseSafety(t *testing.T) {
	upgrader := Upgrader{}
	for _, tc := range []struct {
		name       string
		protoMajor int
		proto      string
		method     string
		host       string
		headers    http.Header
		respHdr    http.Header
		wantStatus int
	}{
		{"unsupported_http4", 4, "HTTP/4.0", http.MethodConnect, "localhost", http.Header{":protocol": {"websocket"}, "Sec-Websocket-Version": {"13"}}, nil, http.StatusHTTPVersionNotSupported},
		{"non_connect_method", 2, "HTTP/2.0", http.MethodGet, "localhost", http.Header{":protocol": {"websocket"}, "Sec-Websocket-Version": {"13"}}, nil, http.StatusMethodNotAllowed},
		{"missing_authority", 2, "HTTP/2.0", http.MethodConnect, "", http.Header{":protocol": {"websocket"}, "Sec-Websocket-Version": {"13"}, "Origin": {"null"}}, nil, http.StatusBadRequest},
		{"userinfo_authority", 2, "HTTP/2.0", http.MethodConnect, "user@localhost", http.Header{":protocol": {"websocket"}, "Sec-Websocket-Version": {"13"}}, nil, http.StatusBadRequest},
		{"missing_protocol_h2", 2, "HTTP/2.0", http.MethodConnect, "localhost", http.Header{"Sec-Websocket-Version": {"13"}}, nil, http.StatusBadRequest},
		{"missing_protocol_h3", 3, "HTTP/3.0", http.MethodConnect, "localhost", http.Header{"Sec-Websocket-Version": {"13"}}, nil, http.StatusBadRequest},
		{"bad_version", 2, "HTTP/2.0", http.MethodConnect, "localhost", http.Header{":protocol": {"websocket"}, "Sec-Websocket-Version": {"8"}}, nil, http.StatusBadRequest},
		{"resp_extensions_rejected", 2, "HTTP/2.0", http.MethodConnect, "localhost", http.Header{":protocol": {"websocket"}, "Sec-Websocket-Version": {"13"}}, http.Header{"Sec-Websocket-Extensions": {"permessage-deflate"}}, http.StatusInternalServerError},
		{"cross_origin", 2, "HTTP/2.0", http.MethodConnect, "localhost", http.Header{":protocol": {"websocket"}, "Sec-Websocket-Version": {"13"}, "Origin": {"https://evil.example"}}, nil, http.StatusForbidden},
		{"null_origin", 2, "HTTP/2.0", http.MethodConnect, "localhost", http.Header{":protocol": {"websocket"}, "Sec-Websocket-Version": {"13"}, "Origin": {"null"}}, nil, http.StatusForbidden},
		{"multiple_origins", 2, "HTTP/2.0", http.MethodConnect, "localhost", http.Header{":protocol": {"websocket"}, "Sec-Websocket-Version": {"13"}, "Origin": {"https://localhost", "https://evil.example"}}, nil, http.StatusForbidden},
		{"unicode_kelvin_fold", 2, "HTTP/2.0", http.MethodConnect, "localhosk", http.Header{":protocol": {"websocket"}, "Sec-Websocket-Version": {"13"}, "Origin": {"https://localhos\u212a"}}, nil, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cr, cw := io.Pipe()
			sr, sw := io.Pipe()
			defer cr.Close()
			defer cw.Close()
			defer sr.Close()
			defer sw.Close()
			go io.Copy(io.Discard, sr)

			req, _ := http.NewRequest(tc.method, "https://localhost/ws", cr)
			req.ProtoMajor = tc.protoMajor
			req.Proto = tc.proto
			req.Host = tc.host
			req.Header = tc.headers

			mw := newMockStreamResponseWriter(sw)
			if _, err := upgrader.Upgrade(mw, req, tc.respHdr); err == nil {
				t.Fatal("expected error")
			}
			if mw.status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", mw.status, tc.wantStatus)
			}
		})
	}

	t.Run("fragment_int64_overflow_and_1byte_close", func(t *testing.T) {
		cr, cw := io.Pipe()
		sr, sw := io.Pipe()
		defer cr.Close()
		defer cw.Close()
		defer sr.Close()
		defer sw.Close()
		go io.Copy(io.Discard, sr)

		mw := newMockStreamResponseWriter(sw)
		sc := newTestStreamNetConn(mw, cr)
		conn := newConn(sc, true, 1024, 1024, nil, nil, nil)
		conn.SetReadLimit(65536)

		go func() {
			_, _ = cw.Write(buildTestFrame(false, BinaryMessage, 0, true, []byte("A")))
			var hdr [14]byte
			hdr[0] = 0x80 | continuationFrame
			hdr[1] = 0x80 | 127
			binary.BigEndian.PutUint64(hdr[2:10], uint64(math.MaxInt64))
			_, _ = cw.Write(hdr[:])
		}()
		if _, _, err := conn.ReadMessage(); !errors.Is(err, ErrReadLimit) {
			t.Fatalf("overflow ReadMessage = %v, want ErrReadLimit", err)
		}
		_ = conn.Close()

		// 1-byte close frame must fail with protocol error
		cr2, cw2 := io.Pipe()
		sr2, sw2 := io.Pipe()
		defer cr2.Close()
		defer cw2.Close()
		defer sr2.Close()
		defer sw2.Close()
		mw2 := newMockStreamResponseWriter(sw2)
		sc2 := newTestStreamNetConn(mw2, cr2)
		conn2 := newConn(sc2, true, 1024, 1024, nil, nil, nil)
		defer conn2.Close()

		closeCodeCh := make(chan int, 1)
		go func() {
			_, op, _, payload, err := readTestServerFrame(sr2)
			if err == nil && op == CloseMessage && len(payload) >= 2 {
				closeCodeCh <- int(binary.BigEndian.Uint16(payload[:2]))
			}
		}()
		go func() {
			_, _ = cw2.Write(buildTestFrame(true, CloseMessage, 0, true, []byte{0x03}))
		}()
		if _, _, err := conn2.ReadMessage(); err == nil {
			t.Fatal("expected error for 1-byte close frame")
		}
		if code := <-closeCodeCh; code != CloseProtocolError {
			t.Fatalf("close code = %d, want %d", code, CloseProtocolError)
		}
	})

	t.Run("concurrent_ops_against_close_and_handler_exit", func(t *testing.T) {
		for range 25 {
			cr, cw := io.Pipe()
			sr, sw := io.Pipe()
			go io.Copy(io.Discard, sr)

			mw := newMockStreamResponseWriter(sw)
			sc := newTestStreamNetConn(mw, cr)
			conn := newConn(sc, true, 1024, 1024, nil, nil, nil)

			var wg sync.WaitGroup
			wg.Add(4)
			go func() {
				defer wg.Done()
				for range 20 {
					_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				}
			}()
			go func() {
				defer wg.Done()
				for i := range 20 {
					// SetWriteDeadline must not be called concurrently with other write methods.
					_ = conn.SetWriteDeadline(time.Now().Add(time.Duration(i%2*2-1) * time.Millisecond))
					_ = conn.WriteMessage(BinaryMessage, []byte("msg"))
				}
			}()
			go func() {
				defer wg.Done()
				for range 20 {
					_ = conn.WriteControl(PingMessage, []byte("p"), time.Now().Add(50*time.Millisecond))
				}
			}()
			go func() {
				defer wg.Done()
				_, _ = cw.Write(buildTestFrame(true, PingMessage, 0, true, []byte("p")))
				_, _, _ = conn.NextReader()
			}()

			_ = conn.Close()
			mw.handlerExited.Store(true)

			wg.Wait()
			_ = cw.Close()
			_ = sr.Close()
			_ = sw.Close()
		}
	})

	t.Run("use_after_handler_exit_without_close", func(t *testing.T) {
		cr, cw := io.Pipe()
		sr, sw := io.Pipe()
		defer cr.Close()
		defer cw.Close()
		defer sr.Close()
		defer sw.Close()
		go io.Copy(io.Discard, sr)

		mw := newMockStreamResponseWriter(sw)
		conn := newConn(newTestStreamNetConn(mw, cr), true, 1024, 1024, nil, nil, nil)
		mw.handlerExited.Store(true) // the mock panics when used after this

		if err := conn.WriteMessage(TextMessage, []byte("x")); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("WriteMessage = %v, want net.ErrClosed", err)
		}
		if err := conn.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("SetReadDeadline = %v, want net.ErrClosed", err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("Close = %v", err)
		}
	})
}

// reexecWithH2XConnect re-runs the current top-level test in a subprocess with
// GODEBUG=http2xconnect=1, which enables HTTP/2 Extended CONNECT in net/http on
// Go 1.24-1.27. It reports whether the caller should return.
func reexecWithH2XConnect(t *testing.T) bool {
	for _, part := range strings.Split(os.Getenv("GODEBUG"), ",") {
		if strings.TrimSpace(part) == "http2xconnect=1" {
			return false
		}
	}
	godebug := "http2xconnect=1"
	if v := os.Getenv("GODEBUG"); v != "" {
		godebug = v + "," + godebug
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), "GODEBUG="+godebug)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	return true
}

// h2TestClient is a minimal HTTP/2 client that can send Extended CONNECT
// requests.
type h2TestClient struct {
	t    *testing.T
	conn *tls.Conn
}

func dialH2TestServer(t *testing.T, h http.Handler) *h2TestClient {
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &h2TestClient{t: t, conn: conn}

	if _, err := io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	c.writeFrame(0x4, 0, 0, nil)
	for {
		typ, flags, _, p := c.readFrame()
		if typ != 0x4 || flags&0x1 != 0 {
			continue
		}
		gotXConnect := false
		for i := 0; i+6 <= len(p); i += 6 {
			if binary.BigEndian.Uint16(p[i:i+2]) == 0x8 && binary.BigEndian.Uint32(p[i+2:i+6]) == 1 {
				gotXConnect = true
			}
		}
		if !gotXConnect {
			t.Fatal("missing ENABLE_CONNECT_PROTOCOL=1")
		}
		c.writeFrame(0x4, 0x1, 0, nil)
		return c
	}
}

func (c *h2TestClient) writeFrame(typ, flags byte, streamID uint32, p []byte) {
	var h [9]byte
	n := len(p)
	h[0], h[1], h[2] = byte(n>>16), byte(n>>8), byte(n)
	h[3], h[4] = typ, flags
	binary.BigEndian.PutUint32(h[5:9], streamID)
	if _, err := c.conn.Write(append(h[:], p...)); err != nil {
		c.t.Fatal(err)
	}
}

func (c *h2TestClient) readFrame() (typ, flags byte, streamID uint32, p []byte) {
	var h [9]byte
	if _, err := io.ReadFull(c.conn, h[:]); err != nil {
		c.t.Fatal(err)
	}
	p = make([]byte, int(h[0])<<16|int(h[1])<<8|int(h[2]))
	if _, err := io.ReadFull(c.conn, p); err != nil {
		c.t.Fatal(err)
	}
	return h[3], h[4], binary.BigEndian.Uint32(h[5:9]) & 0x7fffffff, p
}

// connect sends an Extended CONNECT request for /ws on stream 1 and returns
// the first byte of the response header block: 0x88 for :status 200 and 0x8e
// for :status 500 (HPACK static table).
func (c *h2TestClient) connect() byte {
	// Literal HPACK headers without indexing.
	var hb bytes.Buffer
	for _, kv := range [][2]string{
		{":method", "CONNECT"},
		{":protocol", "websocket"},
		{":scheme", "https"},
		{":authority", c.conn.RemoteAddr().String()},
		{":path", "/ws"},
		{"sec-websocket-version", "13"},
	} {
		hb.WriteByte(0x00)
		hb.WriteByte(byte(len(kv[0])))
		hb.WriteString(kv[0])
		hb.WriteByte(byte(len(kv[1])))
		hb.WriteString(kv[1])
	}
	c.writeFrame(0x1, 0x4, 1, hb.Bytes())
	for {
		typ, _, sid, p := c.readFrame()
		if typ == 0x1 && sid == 1 {
			if len(p) == 0 {
				c.t.Fatal("empty HEADERS frame")
			}
			return p[0]
		}
	}
}

func TestNetHTTP2EndToEnd(t *testing.T) {
	if reexecWithH2XConnect(t) {
		return
	}
	upgrader := Upgrader{EnableCompression: true}
	c := dialH2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, p, err := c.ReadMessage()
			if err != nil {
				return
			}
			if err := c.WriteMessage(mt, p); err != nil {
				return
			}
		}
	}))
	if status := c.connect(); status != 0x88 {
		t.Fatalf("expected :status 200 (0x88), got %x", status)
	}

	// Echo binary WebSocket frame over HTTP/2 stream 1
	wsMsg := []byte("hello over net/http h2")
	c.writeFrame(0x0, 0, 1, buildTestFrame(true, BinaryMessage, 0, true, wsMsg))
	var dataBuf bytes.Buffer
	for dataBuf.Len() < 2+len(wsMsg) {
		typ, _, sid, p := c.readFrame()
		if typ == 0x0 && sid == 1 {
			dataBuf.Write(p)
		}
	}
	fin, op, _, gotPayload, err := readTestServerFrame(&dataBuf)
	if err != nil || !fin || op != BinaryMessage || !bytes.Equal(gotPayload, wsMsg) {
		t.Fatalf("echo = (%v, %d, %q, %v)", fin, op, gotPayload, err)
	}
	c.writeFrame(0x0, 0x1, 1, buildTestFrame(true, CloseMessage, 0, true, FormatCloseMessage(CloseNormalClosure, "")))
}

// raceEnabled is set when the race detector is enabled.
var raceEnabled bool

// TestNetHTTP2HandlerReturnsEarly verifies that using a connection after the
// handler returned without calling Close reports an error instead of crashing
// the process. Go's HTTP/2 server panics when a ResponseWriter is used after
// the handler returned. This misuse is inherently a data race with the HTTP
// server, so the test can't run under the race detector.
func TestNetHTTP2HandlerReturnsEarly(t *testing.T) {
	if raceEnabled {
		t.Skip("data race by design")
	}
	if reexecWithH2XConnect(t) {
		return
	}
	var upgrader Upgrader
	errs := make(chan error, 3)
	c := dialH2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			errs <- err
			return
		}
		go func() {
			<-r.Context().Done()
			time.Sleep(50 * time.Millisecond) // let the server finish the handler
			errs <- conn.WriteMessage(TextMessage, []byte("hello"))
			errs <- conn.SetReadDeadline(time.Now().Add(time.Second))
			errs <- conn.Close()
		}()
	}))
	if status := c.connect(); status != 0x88 {
		t.Fatalf("expected :status 200 (0x88), got %x", status)
	}
	for _, want := range []error{net.ErrClosed, net.ErrClosed, nil} {
		if err := <-errs; !errors.Is(err, want) {
			t.Fatalf("got %v, want %v", err, want)
		}
	}
}

// TestNetHTTP2ServeClosesBeforeReturn verifies that goroutines that outlive
// the function passed to Upgrader.Serve get net.ErrClosed without racing with
// the HTTP server.
func TestNetHTTP2ServeClosesBeforeReturn(t *testing.T) {
	if reexecWithH2XConnect(t) {
		return
	}
	var upgrader Upgrader
	errs := make(chan error, 1)
	c := dialH2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served := make(chan struct{})
		defer close(served)
		err := upgrader.Serve(w, r, nil, func(conn *Conn) {
			go func() {
				<-served
				errs <- conn.WriteMessage(TextMessage, []byte("hello"))
			}()
		})
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	}))
	if status := c.connect(); status != 0x88 {
		t.Fatalf("expected :status 200 (0x88), got %x", status)
	}
	if err := <-errs; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteMessage after Serve returned = %v, want net.ErrClosed", err)
	}
}

// TestNetHTTP2CloseAbortsWriteAfterContextCancel verifies that Close unblocks
// a pending write when middleware has canceled the request context while the
// handler is still running.
func TestNetHTTP2CloseAbortsWriteAfterContextCancel(t *testing.T) {
	if reexecWithH2XConnect(t) {
		return
	}
	var upgrader Upgrader
	results := make(chan string, 2)
	c := dialH2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context()) // e.g. timeout middleware
		defer cancel()
		r = r.WithContext(ctx)
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Upgrade: %v", err)
			return
		}
		writeDone := make(chan error, 1)
		go func() {
			// The client never sends WINDOW_UPDATE, so this blocks.
			writeDone <- conn.WriteMessage(BinaryMessage, make([]byte, 1<<20))
		}()
		time.Sleep(100 * time.Millisecond)
		cancel()

		closeDone := make(chan struct{})
		go func() {
			conn.Close()
			close(closeDone)
		}()
		select {
		case <-closeDone:
			results <- "closed"
		case <-time.After(5 * time.Second):
			results <- "Close blocked"
			return
		}
		if err := <-writeDone; err == nil {
			results <- "write succeeded"
		} else {
			results <- "write failed"
		}
	}))
	if status := c.connect(); status != 0x88 {
		t.Fatalf("expected :status 200 (0x88), got %x", status)
	}
	// Drain frames without granting flow-control credit.
	go io.Copy(io.Discard, c.conn)
	if got := <-results; got != "closed" {
		t.Fatal(got)
	}
	if got := <-results; got != "write failed" {
		t.Fatal(got)
	}
}

// noUnwrapResponseWriter is typical logging middleware: it implements Flush
// but not Unwrap, which hides the stream's deadlines.
type noUnwrapResponseWriter struct{ http.ResponseWriter }

func (w noUnwrapResponseWriter) Flush() { w.ResponseWriter.(http.Flusher).Flush() }

func TestNetHTTP2RequiresDeadlines(t *testing.T) {
	if reexecWithH2XConnect(t) {
		return
	}
	var upgrader Upgrader
	upgradeErr := make(chan error, 1)
	c := dialH2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(noUnwrapResponseWriter{w}, r, nil)
		if err == nil {
			conn.Close()
		}
		upgradeErr <- err
	}))
	if status := c.connect(); status != 0x8e {
		t.Fatalf("expected :status 500 (0x8e), got %x", status)
	}
	if err := <-upgradeErr; err == nil || !strings.Contains(err.Error(), "deadlines") {
		t.Fatalf("Upgrade error = %v, want deadline error", err)
	}
}
