[![Tests](https://github.com/c2FmZQ/websocket/actions/workflows/pr.yml/badge.svg)](https://github.com/c2FmZQ/websocket/actions/workflows/pr.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/c2FmZQ/websocket.svg)](https://pkg.go.dev/github.com/c2FmZQ/websocket)

# WebSocket (`github.com/c2FmZQ/websocket`)

`github.com/c2FmZQ/websocket` is a fork of [gorilla/websocket](https://github.com/gorilla/websocket) that adds server-side support for:

* **WebSocket over HTTP/2** ([RFC 8441](https://www.rfc-editor.org/rfc/rfc8441) Extended `CONNECT`, including cleartext `h2c`)
* **WebSocket over HTTP/3** ([RFC 9220](https://www.rfc-editor.org/rfc/rfc9220) Extended `CONNECT`, compatible with [`quic-go/http3`](https://pkg.go.dev/github.com/quic-go/quic-go/http3))

`Upgrader.Upgrade` returns a concrete `*websocket.Conn` across HTTP/1.1, HTTP/2, and HTTP/3, preserving drop-in API compatibility with `gorilla/websocket`—including subprotocol negotiation, `permessage-deflate` compression ([RFC 7692](https://www.rfc-editor.org/rfc/rfc7692)), `PreparedMessage`, `WriteBufferPool`, and JSON helpers—with no additional runtime dependencies.

## Installation

```bash
go get github.com/c2FmZQ/websocket
```

## HTTP/2 & HTTP/3 Server Notes

1. **Enabling Extended `CONNECT` in Go's `net/http` (HTTP/2):**
   Go's standard library `net/http` server disables RFC 8441 (`SETTINGS_ENABLE_CONNECT_PROTOCOL`) by default starting in Go 1.24.

   * **Go 1.28+ ([`golang/go@e29e95265674`](https://github.com/golang/go/commit/e29e952656742101da216fb8ed8e494eee7abe29), [go.dev/issue/53208](https://go.dev/issue/53208)):** Enable Extended `CONNECT` per server via `http.HTTP2Config.EnableConnectProtocol` (not yet in a released Go version as of Go 1.27):

     ```go
     srv := &http.Server{
         Handler: mux,
         HTTP2: &http.HTTP2Config{
             EnableConnectProtocol: true,
         },
     }
     ```

   * **Go 1.24–1.27:** `HTTP2Config.EnableConnectProtocol` is not yet available, and `http2xconnect` cannot be set via `//go:debug`. Set `GODEBUG=http2xconnect=1` in the environment at process startup, or import the `h2xconnect` helper package before any package that imports `net/http`:

     ```go
     import (
         _ "github.com/c2FmZQ/websocket/h2xconnect"
     )
     ```

   (`quic-go/http3.Server` advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` by default.)

2. **Route registration:**
   HTTP/1.1 WebSocket handshakes use `GET`, whereas HTTP/2 and HTTP/3 Extended `CONNECT` handshakes use `CONNECT`. When using method-specific `http.ServeMux` patterns, register both:

   ```go
   mux.HandleFunc("GET /ws", handleWS)
   mux.HandleFunc("CONNECT /ws", handleWS)
   ```

3. **Handler lifetime (differs from `gorilla/websocket`):**
   Over HTTP/2 and HTTP/3, the underlying stream is tied to the lifetime of `http.Handler.ServeHTTP`. The common gorilla pattern of starting read/write goroutines and returning from the handler does **not** work. Keep `ServeHTTP` active for the duration of the WebSocket session and close the connection before returning. `Upgrader.Serve` does both:

   ```go
   func handleWS(w http.ResponseWriter, r *http.Request) {
       upgrader.Serve(w, r, nil, func(conn *websocket.Conn) {
           // Read/write using conn. The connection is closed when this returns.
       })
   }
   ```

   After `Close` returns, the connection's methods return `net.ErrClosed`, so goroutines that still hold it are safe. Returning from the handler *without* calling `Close` while another goroutine uses the connection is a data race with the HTTP server.

4. **Middleware:**
   Any middleware that wraps `http.ResponseWriter` must implement `Unwrap() http.ResponseWriter` so that `http.ResponseController` can reach the stream's deadlines and flushing. Without deadlines, a peer could block the connection forever, so `Upgrade` rejects HTTP/2 and HTTP/3 requests with `500 Internal Server Error` when they are unavailable.

## License

BSD-2-Clause (see [LICENSE](LICENSE)).
