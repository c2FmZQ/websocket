// Copyright 2014 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var hostPortNoPortTests = []struct {
	u                    *url.URL
	hostPort, hostNoPort string
}{
	{&url.URL{Scheme: "ws", Host: "example.com"}, "example.com:80", "example.com"},
	{&url.URL{Scheme: "wss", Host: "example.com"}, "example.com:443", "example.com"},
	{&url.URL{Scheme: "ws", Host: "example.com:7777"}, "example.com:7777", "example.com"},
	{&url.URL{Scheme: "wss", Host: "example.com:7777"}, "example.com:7777", "example.com"},
}

func TestHostPortNoPort(t *testing.T) {
	for _, tt := range hostPortNoPortTests {
		hostPort, hostNoPort := hostPortNoPort(tt.u)
		if hostPort != tt.hostPort {
			t.Errorf("hostPortNoPort(%v) returned hostPort %q, want %q", tt.u, hostPort, tt.hostPort)
		}
		if hostNoPort != tt.hostNoPort {
			t.Errorf("hostPortNoPort(%v) returned hostNoPort %q, want %q", tt.u, hostNoPort, tt.hostNoPort)
		}
	}
}

func TestDialerRejectsUnsolicitedCompression(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nc, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Fatalf("Hijack: %v", err)
		}
		defer nc.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + computeAcceptKey(r.Header.Get("Sec-Websocket-Key")) + "\r\n" +
			"Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n\r\n")
		_ = brw.Flush()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	d := Dialer{EnableCompression: false}
	c, _, err := d.Dial(wsURL, nil)
	if !errors.Is(err, errInvalidCompression) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("Dial() error = %v, want %v", err, errInvalidCompression)
	}
}

func TestHTTPProxyDialerMalformedStatusNoPanic(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		br := bufio.NewReader(c2)
		_, _ = http.ReadRequest(br)
		_, _ = io.WriteString(c2, "HTTP/1.1 407\r\n\r\n")
	}()

	proxyURL, _ := url.Parse("http://proxy.example.com:8080")
	hpd := &httpProxyDialer{
		proxyURL: proxyURL,
		forwardDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return c1, nil
		},
	}
	conn, err := hpd.DialContext(context.Background(), "tcp", "example.com:80")
	if err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("expected error for 407 proxy response, got nil")
	}
}

func TestDialerRejectsNonCanonicalDuplicateHeader(t *testing.T) {
	d := Dialer{}
	c, _, err := d.Dial("ws://example.com", http.Header{"upgrade": {"websocket"}})
	if err == nil {
		if c != nil {
			c.Close()
		}
		t.Fatal("expected duplicate header error, got nil")
	}
}

// writeEndlessHeaders writes an HTTP response status line followed by header
// lines until a write fails.
func writeEndlessHeaders(w io.Writer, status string) {
	line := "X-Filler: " + strings.Repeat("a", 1000) + "\r\n"
	if _, err := io.WriteString(w, status+"\r\n"); err != nil {
		return
	}
	for {
		if _, err := io.WriteString(w, line); err != nil {
			return
		}
	}
}

func TestDialerRejectsOversizedHandshakeResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nc, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		defer nc.Close()
		writeEndlessHeaders(nc, "HTTP/1.1 101 Switching Protocols")
	}))
	defer srv.Close()

	var d Dialer
	c, _, err := d.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if !errors.Is(err, errHandshakeResponseTooLarge) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("Dial() error = %v, want %v", err, errHandshakeResponseTooLarge)
	}
}

func TestHTTPProxyDialerRejectsOversizedResponse(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		_, _ = http.ReadRequest(bufio.NewReader(c2))
		writeEndlessHeaders(c2, "HTTP/1.1 200 OK")
	}()

	proxyURL, _ := url.Parse("http://proxy.example.com:8080")
	hpd := &httpProxyDialer{
		proxyURL: proxyURL,
		forwardDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return c1, nil
		},
	}
	conn, err := hpd.DialContext(context.Background(), "tcp", "example.com:80")
	if !errors.Is(err, errHandshakeResponseTooLarge) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("DialContext() error = %v, want %v", err, errHandshakeResponseTooLarge)
	}
}

// TestDialerReadsLargeMessages verifies that the handshake response size limit
// does not apply after the handshake.
func TestDialerReadsLargeMessages(t *testing.T) {
	msg := bytes.Repeat([]byte("x"), 2*maxHandshakeResponseSize)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var u Upgrader
		c, err := u.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteMessage(BinaryMessage, msg)
	}))
	defer srv.Close()

	var d Dialer
	c, _, err := d.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if _, p, err := c.ReadMessage(); err != nil || !bytes.Equal(p, msg) {
		t.Fatalf("ReadMessage = (len=%d, %v), want len=%d", len(p), err, len(msg))
	}
}

// TestDialContextCancelDuringHandshake verifies that canceling the context
// aborts a handshake with a server that never responds.
func TestDialContextCancelDuringHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // never respond
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	var d Dialer
	c, _, err := d.DialContext(ctx, "ws://"+ln.Addr().String(), nil)
	if !errors.Is(err, context.Canceled) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("DialContext() error = %v, want %v", err, context.Canceled)
	}
}

func TestHTTPProxyDialerCancel(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		_, _ = http.ReadRequest(bufio.NewReader(c2)) // never respond
	}()

	proxyURL, _ := url.Parse("http://proxy.example.com:8080")
	hpd := &httpProxyDialer{
		proxyURL: proxyURL,
		forwardDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return c1, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	conn, err := hpd.DialContext(ctx, "tcp", "example.com:80")
	if !errors.Is(err, context.Canceled) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("DialContext() error = %v, want %v", err, context.Canceled)
	}
}

// TestDialerDropsFramingHeaders verifies that request framing headers from
// the application never reach the wire, whatever their case.
func TestDialerDropsFramingHeaders(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	reqCh := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var req strings.Builder
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			req.WriteString(line)
			if err != nil || line == "\r\n" {
				break
			}
		}
		reqCh <- req.String()
	}()

	var d Dialer
	_, _, _ = d.Dial("ws://"+ln.Addr().String(), http.Header{
		"content-length":    {"10"},
		"transfer-encoding": {"chunked"},
		"Trailer":           {"X-Foo"},
		"x-custom":          {"ok"},
	})
	req := strings.ToLower(<-reqCh)
	for _, h := range []string{"content-length", "transfer-encoding", "trailer"} {
		if strings.Contains(req, h+":") {
			t.Errorf("request contains %s header:\n%s", h, req)
		}
	}
	if !strings.Contains(req, "x-custom: ok") {
		t.Errorf("request is missing x-custom header:\n%s", req)
	}
}
