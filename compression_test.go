package websocket

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
)

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func TestTruncWriter(t *testing.T) {
	const data = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijlkmnopqrstuvwxyz987654321"
	for n := 1; n <= 10; n++ {
		var b bytes.Buffer
		w := &truncWriter{w: nopCloser{&b}}
		p := []byte(data)
		for len(p) > 0 {
			m := len(p)
			if m > n {
				m = n
			}
			nn, err := w.Write(p[:m])
			if err != nil || nn != m {
				t.Fatalf("Write(%d): got (%d, %v), want (%d, nil)", m, nn, err, m)
			}
			p = p[m:]
		}
		if b.String() != data[:len(data)-len(w.p)] {
			t.Errorf("%d: %q", n, b.String())
		}
	}
}

func textMessages(num int) [][]byte {
	messages := make([][]byte, num)
	for i := 0; i < num; i++ {
		msg := fmt.Sprintf("planet: %d, country: %d, city: %d, street: %d", i, i, i, i)
		messages[i] = []byte(msg)
	}
	return messages
}

func BenchmarkWriteNoCompression(b *testing.B) {
	w := io.Discard
	c := newTestConn(nil, w, false)
	messages := textMessages(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.WriteMessage(TextMessage, messages[i%len(messages)])
	}
	b.ReportAllocs()
}

func BenchmarkWriteWithCompression(b *testing.B) {
	w := io.Discard
	c := newTestConn(nil, w, false)
	messages := textMessages(100)
	c.enableWriteCompression = true
	c.newCompressionWriter = compressNoContextTakeover
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.WriteMessage(TextMessage, messages[i%len(messages)])
	}
	b.ReportAllocs()
}

func TestValidCompressionLevel(t *testing.T) {
	c := newTestConn(nil, nil, false)
	for _, level := range []int{minCompressionLevel - 1, maxCompressionLevel + 1} {
		if err := c.SetCompressionLevel(level); err == nil {
			t.Errorf("no error for level %d", level)
		}
	}
	for _, level := range []int{minCompressionLevel, maxCompressionLevel} {
		if err := c.SetCompressionLevel(level); err != nil {
			t.Errorf("error for level %d", level)
		}
	}
}

func TestDecompressionReadLimit(t *testing.T) {
	const limit = 256

	sendAndRead := func(payload []byte) error {
		var buf bytes.Buffer
		wc := newTestConn(nil, &buf, false)
		wc.enableWriteCompression = true
		wc.newCompressionWriter = compressNoContextTakeover
		if err := wc.WriteMessage(TextMessage, payload); err != nil {
			t.Fatalf("WriteMessage: %v", err)
		}

		rc := newTestConn(&buf, io.Discard, true)
		rc.newDecompressionReader = decompressNoContextTakeover
		rc.SetReadLimit(limit)
		_, got, err := rc.ReadMessage()
		if err != nil {
			return err
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("got %d bytes, want %d", len(got), len(payload))
		}
		return nil
	}

	// Exactly at the limit should succeed.
	if err := sendAndRead(bytes.Repeat([]byte("a"), limit)); err != nil {
		t.Fatalf("at limit: unexpected error: %v", err)
	}

	// Highly compressible payload exceeding the limit should return ErrReadLimit
	// even though the compressed wire frame is smaller than limit.
	if err := sendAndRead(bytes.Repeat([]byte("a"), limit*16)); !errors.Is(err, ErrReadLimit) {
		t.Fatalf("over limit: got %v, want %v", err, ErrReadLimit)
	}
}

type failWriter struct {
	err error
}

func (f failWriter) Write(p []byte) (int, error) { return 0, f.err }
func (f failWriter) Close() error                { return nil }

func TestFlateWriteWrapperCloseError(t *testing.T) {
	wantErr := errors.New("write failed")
	var pool sync.Pool
	c := newConn(fakeNetConn{Writer: failWriter{err: wantErr}}, true, 1024, 1024, &pool, nil, nil)
	c.newCompressionWriter = compressNoContextTakeover

	w, err := c.NextWriter(TextMessage)
	if err != nil {
		t.Fatalf("NextWriter: %v", err)
	}
	// Write enough to trigger flate flush/write on Close.
	if _, err := w.Write(bytes.Repeat([]byte("a"), 32)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	err = w.Close()
	if !errors.Is(err, wantErr) {
		t.Fatalf("Close() = %v, want %v", err, wantErr)
	}
	if c.writeBuf != nil {
		t.Fatal("expected writeBuf to be returned to pool on Close error")
	}
}

func TestRSV1RejectedOnControlAndContinuationFrames(t *testing.T) {
	// Client-to-server Ping frame with FIN|RSV1|PingMessage (0x80|0x40|0x09 = 0xc9),
	// masked empty payload (0x80, mask=0,0,0,0).
	raw := []byte{finalBit | rsv1Bit | PingMessage, maskBit, 0, 0, 0, 0}
	rc := newTestConn(bytes.NewReader(raw), io.Discard, true)
	rc.newDecompressionReader = decompressNoContextTakeover
	if _, _, err := rc.NextReader(); err == nil || !errors.Is(err, err) {
		t.Fatalf("expected protocol error for RSV1 on Ping, got %v", err)
	}

	// Client-to-server unfragmented TextMessage without FIN (0x01) followed by
	// continuation frame with RSV1 set (0x80|0x40|0x00 = 0xc0).
	raw2 := []byte{
		TextMessage, maskBit, 0, 0, 0, 0,
		finalBit | rsv1Bit | continuationFrame, maskBit, 0, 0, 0, 0,
	}
	rc2 := newTestConn(bytes.NewReader(raw2), io.Discard, true)
	rc2.newDecompressionReader = decompressNoContextTakeover
	if _, _, err := rc2.ReadMessage(); err == nil {
		t.Fatal("expected protocol error for RSV1 on continuation frame, got nil")
	}
}
