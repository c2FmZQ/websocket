// Copyright 2026 Robin Thellend <rthellend@rthellend.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package h3test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/c2FmZQ/websocket"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func buildClientWSFrame(opcode byte, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x80 | opcode)
	n := len(payload)
	switch {
	case n < 126:
		b.WriteByte(0x80 | byte(n))
	case n <= 65535:
		b.WriteByte(0x80 | 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		b.Write(ext[:])
	default:
		b.WriteByte(0x80 | 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		b.Write(ext[:])
	}
	mask := [4]byte{0xaa, 0xbb, 0xcc, 0xdd}
	b.Write(mask[:])
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i&3]
	}
	b.Write(masked)
	return b.Bytes()
}

func readServerWSFrame(r io.Reader) (byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	if hdr[1]&0x80 != 0 {
		return 0, nil, errors.New("unexpected masked server frame")
	}
	n := int(hdr[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		n = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		n = int(binary.BigEndian.Uint64(ext[:]))
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	return hdr[0] & 0x0f, p, nil
}

func TestWebSocketOverHTTP3QuicGo(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	upgrader := websocket.Upgrader{
		Subprotocols: []string{"h3-ws"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("CONNECT /ws", func(w http.ResponseWriter, r *http.Request) {
		if !websocket.IsWebSocketUpgrade(r) {
			http.Error(w, "not websocket", http.StatusBadRequest)
			return
		}
		conn, err := upgrader.Upgrade(w, r, http.Header{"X-H3-Test": {"ok"}})
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			mt, p, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(mt, append([]byte("h3:"), p...)); err != nil {
				return
			}
		}
	})

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	h3Srv := &http3.Server{
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{tlsCert}}),
		Handler:   mux,
	}
	defer h3Srv.Close()
	go func() {
		_ = h3Srv.Serve(udpConn)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	qconn, err := quic.DialAddr(ctx, udpConn.LocalAddr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, nil)
	if err != nil {
		t.Fatalf("quic.DialAddr: %v", err)
	}
	defer qconn.CloseWithError(0, "")

	tr := &http3.Transport{}
	cc := tr.NewClientConn(qconn)

	// 1. Cross-origin request over HTTP/3 must be rejected with 403.
	badStr, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatalf("OpenRequestStream bad: %v", err)
	}
	badReq, _ := http.NewRequest(http.MethodConnect, "https://"+udpConn.LocalAddr().String()+"/ws", nil)
	badReq.Proto = "websocket"
	badReq.Header.Set("Sec-WebSocket-Version", "13")
	badReq.Header.Set("Origin", "https://evil.example.com")
	if err := badStr.SendRequestHeader(badReq); err != nil {
		t.Fatalf("SendRequestHeader bad: %v", err)
	}
	badResp, err := badStr.ReadResponse()
	if err != nil || badResp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin H3 resp = (%v, %v), want 403", badResp, err)
	}

	// 2. Valid RFC 9220 WebSocket session over HTTP/3.
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatalf("OpenRequestStream: %v", err)
	}
	req, _ := http.NewRequest(http.MethodConnect, "https://"+udpConn.LocalAddr().String()+"/ws", nil)
	req.Proto = "websocket"
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Protocol", "other, h3-ws")
	req.Header.Set("Origin", "https://"+udpConn.LocalAddr().String())
	if err := str.SendRequestHeader(req); err != nil {
		t.Fatalf("SendRequestHeader: %v", err)
	}
	resp, err := str.ReadResponse()
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("Sec-WebSocket-Protocol") != "h3-ws" {
		t.Fatalf("Sec-WebSocket-Protocol = %q, want h3-ws", resp.Header.Get("Sec-WebSocket-Protocol"))
	}
	if resp.Header.Get("X-H3-Test") != "ok" {
		t.Fatalf("X-H3-Test = %q, want ok", resp.Header.Get("X-H3-Test"))
	}

	// Ping -> automatic Pong
	if _, err := str.Write(buildClientWSFrame(websocket.PingMessage, []byte("h3ping"))); err != nil {
		t.Fatalf("Write Ping: %v", err)
	}
	op, p, err := readServerWSFrame(str)
	if err != nil || op != websocket.PongMessage || string(p) != "h3ping" {
		t.Fatalf("Pong = (%d, %q, %v)", op, p, err)
	}

	// Binary message echo (including >4KB payload)
	bigMsg := bytes.Repeat([]byte("quic-ws-frame-"), 500)
	if _, err := str.Write(buildClientWSFrame(websocket.BinaryMessage, bigMsg)); err != nil {
		t.Fatalf("Write Binary: %v", err)
	}
	op, p, err = readServerWSFrame(str)
	if err != nil || op != websocket.BinaryMessage || !bytes.Equal(p, append([]byte("h3:"), bigMsg...)) {
		t.Fatalf("Echo = (%d, len=%d, %v)", op, len(p), err)
	}

	// Clean Close handshake
	_, _ = str.Write(buildClientWSFrame(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done")))
	op, _, err = readServerWSFrame(str)
	if err != nil || op != websocket.CloseMessage {
		t.Fatalf("Close reply = (%d, %v)", op, err)
	}
	_ = str.Close()
}
