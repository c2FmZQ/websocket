// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

var subprotocolTests = []struct {
	h         string
	protocols []string
}{
	{"", nil},
	{"foo", []string{"foo"}},
	{"foo,bar", []string{"foo", "bar"}},
	{"foo, bar", []string{"foo", "bar"}},
	{" foo, bar", []string{"foo", "bar"}},
	{" foo, bar ", []string{"foo", "bar"}},
}

func TestSubprotocols(t *testing.T) {
	for _, st := range subprotocolTests {
		r := http.Request{Header: http.Header{"Sec-Websocket-Protocol": {st.h}}}
		protocols := Subprotocols(&r)
		if !reflect.DeepEqual(st.protocols, protocols) {
			t.Errorf("SubProtocols(%q) returned %#v, want %#v", st.h, protocols, st.protocols)
		}
	}
}

var isWebSocketUpgradeTests = []struct {
	ok bool
	h  http.Header
}{
	{false, http.Header{"Upgrade": {"websocket"}}},
	{false, http.Header{"Connection": {"upgrade"}}},
	{true, http.Header{"Connection": {"upgRade"}, "Upgrade": {"WebSocket"}}},
}

func TestIsWebSocketUpgrade(t *testing.T) {
	for _, tt := range isWebSocketUpgradeTests {
		ok := IsWebSocketUpgrade(&http.Request{Header: tt.h})
		if tt.ok != ok {
			t.Errorf("IsWebSocketUpgrade(%v) returned %v, want %v", tt.h, ok, tt.ok)
		}
	}
}

func TestSubProtocolSelection(t *testing.T) {
	upgrader := Upgrader{
		Subprotocols: []string{"foo", "bar", "baz"},
	}

	r := http.Request{Header: http.Header{"Sec-Websocket-Protocol": {"foo", "bar"}}}
	s := upgrader.selectSubprotocol(&r, nil)
	if s != "foo" {
		t.Errorf("Upgrader.selectSubprotocol returned %v, want %v", s, "foo")
	}

	r = http.Request{Header: http.Header{"Sec-Websocket-Protocol": {"bar", "foo"}}}
	s = upgrader.selectSubprotocol(&r, nil)
	if s != "bar" {
		t.Errorf("Upgrader.selectSubprotocol returned %v, want %v", s, "bar")
	}

	r = http.Request{Header: http.Header{"Sec-Websocket-Protocol": {"baz"}}}
	s = upgrader.selectSubprotocol(&r, nil)
	if s != "baz" {
		t.Errorf("Upgrader.selectSubprotocol returned %v, want %v", s, "baz")
	}

	r = http.Request{Header: http.Header{"Sec-Websocket-Protocol": {"quux"}}}
	s = upgrader.selectSubprotocol(&r, nil)
	if s != "" {
		t.Errorf("Upgrader.selectSubprotocol returned %v, want %v", s, "empty string")
	}
}

var checkSameOriginTests = []struct {
	ok bool
	r  *http.Request
}{
	{false, &http.Request{Host: "example.org", Header: map[string][]string{"Origin": {"https://other.org"}}}},
	{false, &http.Request{Host: "example.org", Header: map[string][]string{"Origin": {"https://attacker.com@example.org"}}}},
	{true, &http.Request{Host: "example.org", Header: map[string][]string{"Origin": {"https://example.org"}}}},
	{true, &http.Request{Host: "Example.org", Header: map[string][]string{"Origin": {"https://example.org"}}}},
}

func TestCheckSameOrigin(t *testing.T) {
	for _, tt := range checkSameOriginTests {
		ok := checkSameOrigin(tt.r)
		if tt.ok != ok {
			t.Errorf("checkSameOrigin(%+v) returned %v, want %v", tt.r, ok, tt.ok)
		}
	}
}

type reuseTestResponseWriter struct {
	brw *bufio.ReadWriter
	http.ResponseWriter
}

func (resp *reuseTestResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return fakeNetConn{strings.NewReader(""), &bytes.Buffer{}}, resp.brw, nil
}

var bufioReuseTests = []struct {
	n     int
	reuse bool
}{
	{4096, true},
	{128, false},
}

func xTestBufioReuse(t *testing.T) {
	for i, tt := range bufioReuseTests {
		br := bufio.NewReaderSize(strings.NewReader(""), tt.n)
		bw := bufio.NewWriterSize(&bytes.Buffer{}, tt.n)
		resp := &reuseTestResponseWriter{
			brw: bufio.NewReadWriter(br, bw),
		}
		upgrader := Upgrader{}
		c, err := upgrader.Upgrade(resp, &http.Request{
			Method: http.MethodGet,
			Header: http.Header{
				"Upgrade":               []string{"websocket"},
				"Connection":            []string{"upgrade"},
				"Sec-Websocket-Key":     []string{"dGhlIHNhbXBsZSBub25jZQ=="},
				"Sec-Websocket-Version": []string{"13"},
			}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if reuse := c.br == br; reuse != tt.reuse {
			t.Errorf("%d: buffered reader reuse=%v, want %v", i, reuse, tt.reuse)
		}
		writeBuf := bw.AvailableBuffer()
		if reuse := &c.writeBuf[0] == &writeBuf[0]; reuse != tt.reuse {
			t.Errorf("%d: write buffer reuse=%v, want %v", i, reuse, tt.reuse)
		}
	}
}

func TestHijack_NotSupported(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Sec-Websocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-Websocket-Version", "13")

	recorder := httptest.NewRecorder()

	upgrader := Upgrader{}
	_, err := upgrader.Upgrade(recorder, req, nil)

	if want := (HandshakeError{}); !errors.As(err, &want) || recorder.Code != http.StatusInternalServerError {
		t.Errorf("want %T and status_code=%d", want, http.StatusInternalServerError)
		t.Fatalf("got err=%T and status_code=%d", err, recorder.Code)
	}
}

func TestUpgradeResponseHeaderSanitization(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	br := bufio.NewReader(strings.NewReader(""))
	bw := bufio.NewWriter(&out)
	rw := &captureHijackRW{buf: &out, brw: bufio.NewReadWriter(br, bw)}
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Sec-Websocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-Websocket-Version", "13")
	req.Header.Set("Sec-Websocket-Protocol", "chat")

	upgrader := Upgrader{
		Subprotocols: []string{"chat"},
	}
	hdr := http.Header{
		"sec-websocket-protocol": {"evil"},
		"sec-websocket-accept":   {"bad-accept"},
		"Connection":             {"close"},
		"X-Bad\r\nInjected: 1":   {"val\r\nEvil: 2"},
	}
	c, err := upgrader.Upgrade(rw, req, hdr)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	_ = c.Close()

	raw := out.String()
	if strings.Contains(raw, "evil") {
		t.Errorf("non-canonical sec-websocket-protocol was not filtered: %q", raw)
	}
	if strings.Contains(raw, "bad-accept") {
		t.Errorf("sec-websocket-accept was not filtered: %q", raw)
	}
	if strings.Contains(raw, "Connection: close") {
		t.Errorf("forbidden Connection header was not filtered: %q", raw)
	}
	if strings.Contains(raw, "\r\nInjected:") || strings.Contains(raw, "\r\nEvil:") {
		t.Errorf("header injection was not prevented: %q", raw)
	}

	// Verify subprotocol from responseHeader is sanitized when Subprotocols is nil.
	out.Reset()
	rw2 := &captureHijackRW{buf: &out, brw: bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(&out))}
	c2, err := (&Upgrader{}).Upgrade(rw2, req, http.Header{
		"Sec-Websocket-Protocol": {"chat\r\nEvil: 1"},
	})
	if err != nil {
		t.Fatalf("Upgrade 2: %v", err)
	}
	_ = c2.Close()
	if strings.Contains(out.String(), "\r\nEvil:") {
		t.Errorf("subprotocol header injection was not prevented: %q", out.String())
	}

	// Verify non-canonical Sec-WebSocket-Extensions in responseHeader is rejected.
	out.Reset()
	rw3 := &captureHijackRW{buf: &out, brw: bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(&out))}
	if _, err := (&Upgrader{Error: func(http.ResponseWriter, *http.Request, int, error) {}}).Upgrade(rw3, req, http.Header{
		"Sec-WebSocket-Extensions": {"permessage-deflate"},
	}); err == nil {
		t.Fatal("expected error for non-canonical Sec-WebSocket-Extensions in responseHeader")
	}
}

type captureHijackRW struct {
	buf *bytes.Buffer
	brw *bufio.ReadWriter
	http.ResponseWriter
}

func (c *captureHijackRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return fakeNetConn{strings.NewReader(""), c.buf}, c.brw, nil
}

func TestUpgraderServe(t *testing.T) {
	var upgrader Upgrader
	serveErr := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveErr <- upgrader.Serve(w, r, nil, func(c *Conn) {
			mt, p, err := c.ReadMessage()
			if err == nil {
				_ = c.WriteMessage(mt, p)
			}
		})
	}))
	defer srv.Close()

	// Upgrade failure: f is not called and the client gets an error response.
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	var hsErr HandshakeError
	if err := <-serveErr; !errors.As(err, &hsErr) {
		t.Fatalf("Serve() error = %v, want HandshakeError", err)
	}

	// Success: the connection is closed when f returns.
	var d Dialer
	c, _, err := d.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.WriteMessage(TextMessage, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, p, err := c.ReadMessage(); err != nil || string(p) != "hello" {
		t.Fatalf("ReadMessage() = (%q, %v), want hello", p, err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("ReadMessage() after Serve returned: got nil error")
	}
}
