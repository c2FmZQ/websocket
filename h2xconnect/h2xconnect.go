// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package h2xconnect enables HTTP/2 Extended CONNECT (RFC 8441) in GODEBUG
// before net/http initializes, unless http2xconnect is already set in GODEBUG.
//
// In Go 1.24 through Go 1.27, net/http disables RFC 8441 by default unless
// GODEBUG=http2xconnect=1 is present in the environment when net/http
// initializes (and http2xconnect cannot be set via //go:debug). Import this
// package with a blank identifier before any package that imports net/http:
//
//	import (
//		_ "github.com/c2FmZQ/websocket/h2xconnect"
//	)
//
// The setting applies to every net/http HTTP/2 server in the process, and child
// processes inherit it through the environment.
//
// Starting in Go 1.28 (https://go.dev/issue/53208, golang/go commit
// e29e95265674), net/http adds HTTP2Config.EnableConnectProtocol so servers can
// opt in per http.Server without setting GODEBUG:
//
//	srv := &http.Server{
//		Handler: mux,
//		HTTP2: &http.HTTP2Config{
//			EnableConnectProtocol: true,
//		},
//	}
package h2xconnect

import (
	"os"
	"strings"
)

func init() {
	cur := os.Getenv("GODEBUG")
	for _, entry := range strings.Split(cur, ",") {
		if strings.HasPrefix(strings.TrimSpace(entry), "http2xconnect=") {
			return
		}
	}
	if cur == "" {
		_ = os.Setenv("GODEBUG", "http2xconnect=1")
		return
	}
	_ = os.Setenv("GODEBUG", cur+",http2xconnect=1")
}
